"""
Prometheus HTTP API query client.

Wraps the Prometheus ``/api/v1/query`` and ``/api/v1/query_range`` endpoints
to retrieve metrics data for display in Chart.js charts.  Falls back
gracefully when Prometheus is unreachable.
"""

import logging
import time
import zoneinfo
from datetime import datetime, timezone

import requests

from models import Setting


def _user_tz():
    """Return the current user's ZoneInfo or UTC as fallback."""
    try:
        from flask_login import current_user
        if current_user.is_authenticated and current_user.timezone:
            return zoneinfo.ZoneInfo(current_user.timezone)
    except Exception:
        pass
    return timezone.utc

logger = logging.getLogger(__name__)


def _get_jvb_target():
    """Return 'ip:port' for the JVB Prometheus target if scraping is enabled, else None."""
    from apps.exporters import KNOWN_EXPORTERS
    from models import Guest
    if Setting.get("jitsi_prometheus_scrape", "false") != "true":
        return None
    guest_id = Setting.get("jitsi_guest_id", "")
    if not guest_id:
        return None
    try:
        guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        return None
    if not guest or not guest.ip_address or guest.ip_address.lower() in ("dhcp", "dhcp6", "auto"):
        return None
    return f"{guest.ip_address}:{KNOWN_EXPORTERS['jitsi_jvb']['default_port']}"


def _get_exporter_target(guest_id, exporter_type):
    """Return 'ip:port' if the guest has an installed exporter of the given type, else None."""
    from models import ExporterInstance, Guest
    instance = ExporterInstance.query.filter_by(
        guest_id=guest_id, exporter_type=exporter_type, status="installed"
    ).first()
    if not instance:
        return None
    guest = Guest.query.get(guest_id)
    if not guest or not guest.ip_address or guest.ip_address.lower() in ("dhcp", "dhcp6", "auto"):
        return None
    return f"{guest.ip_address}:{instance.port}"

# Map friendly timeframe names to (duration_seconds, step_seconds)
_TIMEFRAMES = {
    "hour": (3600, 60),
    "day": (86400, 300),
    "3d": (259200, 900),
    "week": (604800, 1800),
    "month": (2592000, 7200),
    "3mo": (7776000, 21600),
    "year": (31536000, 86400),
    "365d": (31536000, 86400),
}


class PrometheusQueryClient:
    """Thin client around the Prometheus HTTP API."""

    def __init__(self, base_url=None, timeout=10):
        self.base_url = (base_url or Setting.get("prometheus_url", "")).rstrip("/")
        self.timeout = timeout
        if not self.base_url:
            raise ValueError("Prometheus URL is not configured")

    # ----- low-level -----

    def query(self, promql):
        """Execute an instant query and return the raw result list."""
        resp = requests.get(
            f"{self.base_url}/api/v1/query",
            params={"query": promql},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            raise RuntimeError(f"Prometheus query failed: {data.get('error', 'unknown')}")
        return data.get("data", {}).get("result", [])

    def query_range(self, promql, start, end, step):
        """Execute a range query and return the raw result list.

        *start* and *end* are Unix epoch floats; *step* is seconds.
        """
        resp = requests.get(
            f"{self.base_url}/api/v1/query_range",
            params={"query": promql, "start": start, "end": end, "step": step},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            raise RuntimeError(f"Prometheus range query failed: {data.get('error', 'unknown')}")
        return data.get("data", {}).get("result", [])

    def check_connection(self):
        """Return True if Prometheus is reachable, False otherwise."""
        try:
            resp = requests.get(
                f"{self.base_url}/api/v1/status/buildinfo",
                timeout=5,
            )
            return resp.status_code == 200
        except Exception:
            return False

    # ----- Chart.js helpers -----

    def get_guest_rrd(self, vmid, timeframe="day", guest_id=None):
        """Query Prometheus for guest performance metrics and return Chart.js-ready JSON.

        When *guest_id* is provided and a node_exporter is installed on that guest,
        queries standard node_exporter metrics instead of lambnet_* gauges.
        """
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        rate_interval = f"{max(step * 2, 120)}s"

        # Check for node_exporter
        target = _get_exporter_target(guest_id, "node_exporter") if guest_id else None
        source = "node_exporter" if target else "lambnet"

        if target:
            inst = f'instance="{target}"'
            cpu_data = self._range_single(
                f'100 - (avg(rate(node_cpu_seconds_total{{mode="idle",{inst}}}[{rate_interval}])) * 100)',
                start, end, step,
            )
            mem_used = self._range_single(
                f'node_memory_MemTotal_bytes{{{inst}}} - node_memory_MemAvailable_bytes{{{inst}}}',
                start, end, step,
            )
            mem_total = self._range_single(f'node_memory_MemTotal_bytes{{{inst}}}', start, end, step)
            netin = self._range_single(
                f'sum(rate(node_network_receive_bytes_total{{device!="lo",{inst}}}[{rate_interval}]))',
                start, end, step,
            )
            netout = self._range_single(
                f'sum(rate(node_network_transmit_bytes_total{{device!="lo",{inst}}}[{rate_interval}]))',
                start, end, step,
            )
        else:
            vmid_str = str(vmid)
            cpu_data = self._range_single(f'lambnet_guest_cpu_usage_percent{{vmid="{vmid_str}"}}', start, end, step)
            mem_used = self._range_single(f'lambnet_guest_memory_used_bytes{{vmid="{vmid_str}"}}', start, end, step)
            mem_total = self._range_single(f'lambnet_guest_memory_total_bytes{{vmid="{vmid_str}"}}', start, end, step)
            netin = self._range_single(
                f'lambnet_guest_network_in_bytes_per_sec{{vmid="{vmid_str}"}}', start, end, step,
            )
            netout = self._range_single(
                f'lambnet_guest_network_out_bytes_per_sec{{vmid="{vmid_str}"}}', start, end, step,
            )

        return self._build_guest_result(cpu_data, mem_used, mem_total, netin, netout, source)

    def _build_guest_result(self, cpu_data, mem_used, mem_total, netin, netout, source="lambnet"):
        """Build Chart.js-ready JSON from raw range query results."""
        timestamps = cpu_data.get("timestamps") or mem_used.get("timestamps") or []
        utz = _user_tz()
        labels = [datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(utz).strftime("%Y-%m-%d %H:%M") for ts in timestamps]

        cpu_vals = cpu_data.get("values", [])
        mem_used_vals = mem_used.get("values", [])
        mem_total_vals = mem_total.get("values", [])
        netin_vals = netin.get("values", [])
        netout_vals = netout.get("values", [])

        mem_total_mb = 0
        mem_percent = []
        mem_used_mb = []
        for i, used in enumerate(mem_used_vals):
            total = mem_total_vals[i] if i < len(mem_total_vals) else None
            if used is not None and total and total > 0:
                mem_used_mb.append(round(used / 1048576, 1))
                mem_percent.append(round(used / total * 100, 2))
                mem_total_mb = round(total / 1048576, 1)
            else:
                mem_used_mb.append(None)
                mem_percent.append(None)

        all_net = [v for v in netin_vals + netout_vals if v is not None]
        max_net = max(all_net, default=0)
        if max_net > 1_000_000:
            net_unit = "Mbps"
            divisor = 125_000
        elif max_net > 1_000:
            net_unit = "KB/s"
            divisor = 1024
        else:
            net_unit = "B/s"
            divisor = 1

        if divisor != 1:
            netin_vals = [round(v / divisor, 2) if v is not None else None for v in netin_vals]
            netout_vals = [round(v / divisor, 2) if v is not None else None for v in netout_vals]

        return {
            "labels": labels,
            "cpu": cpu_vals,
            "mem_percent": mem_percent,
            "mem_used_mb": mem_used_mb,
            "mem_total_mb": mem_total_mb,
            "netin": netin_vals,
            "netout": netout_vals,
            "net_unit": net_unit,
            "source": source,
        }

    def get_host_rrd(self, host_id, timeframe="day"):
        """Query Prometheus for host performance metrics and return Chart.js-ready JSON."""
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur

        hid = str(host_id)

        cpu_data = self._range_single(f'lambnet_host_cpu_usage_percent{{host_id="{hid}"}}', start, end, step)
        mem_used = self._range_single(f'lambnet_host_memory_used_bytes{{host_id="{hid}"}}', start, end, step)
        mem_total = self._range_single(f'lambnet_host_memory_total_bytes{{host_id="{hid}"}}', start, end, step)
        netin = self._range_single(f'lambnet_host_network_in_bytes_per_sec{{host_id="{hid}"}}', start, end, step)
        netout = self._range_single(f'lambnet_host_network_out_bytes_per_sec{{host_id="{hid}"}}', start, end, step)
        rootfs = self._range_single(f'lambnet_host_rootfs_used_percent{{host_id="{hid}"}}', start, end, step)

        timestamps = cpu_data.get("timestamps") or mem_used.get("timestamps") or []
        utz = _user_tz()
        labels = [datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(utz).strftime("%Y-%m-%d %H:%M") for ts in timestamps]

        cpu_vals = cpu_data.get("values", [])
        mem_used_vals = mem_used.get("values", [])
        mem_total_vals = mem_total.get("values", [])
        netin_vals = netin.get("values", [])
        netout_vals = netout.get("values", [])
        rootfs_vals = rootfs.get("values", [])

        mem_total_mb = 0
        mem_percent = []
        mem_used_mb = []
        for i, used in enumerate(mem_used_vals):
            total = mem_total_vals[i] if i < len(mem_total_vals) else None
            if used is not None and total and total > 0:
                mem_used_mb.append(round(used / 1048576, 1))
                mem_percent.append(round(used / total * 100, 2))
                mem_total_mb = round(total / 1048576, 1)
            else:
                mem_used_mb.append(None)
                mem_percent.append(None)

        all_net = [v for v in netin_vals + netout_vals if v is not None]
        max_net = max(all_net, default=0)
        if max_net > 1_000_000:
            net_unit = "Mbps"
            divisor = 125_000
        elif max_net > 1_000:
            net_unit = "KB/s"
            divisor = 1024
        else:
            net_unit = "B/s"
            divisor = 1

        if divisor != 1:
            netin_vals = [round(v / divisor, 2) if v is not None else None for v in netin_vals]
            netout_vals = [round(v / divisor, 2) if v is not None else None for v in netout_vals]

        return {
            "labels": labels,
            "cpu": cpu_vals,
            "mem_percent": mem_percent,
            "mem_used_mb": mem_used_mb,
            "mem_total_mb": mem_total_mb,
            "netin": netin_vals,
            "netout": netout_vals,
            "net_unit": net_unit,
            "iowait": [],
            "rootfs_percent": rootfs_vals,
        }

    def get_service_metrics_history(self, service_id, metric_names, timeframe="day"):
        """Query Prometheus for service metric history and return as snapshot list.

        Returns {"snapshots": [{metric: value, "captured_at": iso_str}, ...]}
        matching the format of pg_metrics_history/jvb_metrics_history.
        """
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur

        sid = str(service_id)
        all_series = {}
        timestamps = []

        for metric_name in metric_names:
            result = self._range_single(f'{metric_name}{{service_id="{sid}"}}', start, end, step)
            all_series[metric_name] = result.get("values", [])
            if not timestamps and result.get("timestamps"):
                timestamps = result["timestamps"]

        # Build snapshot list matching the SQLite format
        snapshots = []
        for i, ts in enumerate(timestamps):
            snap = {"captured_at": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()}
            for metric_name, values in all_series.items():
                # Use the short name (strip prefix)
                short = metric_name.split("{")[0].replace("lambnet_", "")
                snap[short] = values[i] if i < len(values) else None
            snapshots.append(snap)

        return {"snapshots": snapshots, "source": "lambnet"}

    def get_pg_metrics_exporter(self, target, timeframe="day"):
        """Query postgres_exporter metrics and return snapshots matching PG format."""
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        inst = f'instance="{target}"'
        rate_interval = f"{max(step * 2, 120)}s"

        queries = {
            "total_connections": f'sum(pg_stat_activity_count{{{inst}}})',
            "active_connections": f'sum(pg_stat_activity_count{{state="active",{inst}}})',
            "cache_hit_ratio": (
                f'sum(rate(pg_stat_database_blks_hit{{{inst}}}[{rate_interval}])) / '
                f'clamp_min(sum(rate(pg_stat_database_blks_hit{{{inst}}}[{rate_interval}])) + '
                f'sum(rate(pg_stat_database_blks_read{{{inst}}}[{rate_interval}])), 1) * 100'
            ),
            "total_commits": f'sum(pg_stat_database_xact_commit{{{inst}}})',
            "total_rollbacks": f'sum(pg_stat_database_xact_rollback{{{inst}}})',
            "lock_waits": f'sum(pg_locks_count{{{inst}}}) or vector(0)',
        }

        return self._run_snapshot_queries(queries, start, end, step, source="postgres_exporter")

    def get_redis_metrics_exporter(self, target, timeframe="day"):
        """Query redis_exporter metrics and return snapshots matching Redis format."""
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        inst = f'instance="{target}"'
        rate_interval = f"{max(step * 2, 120)}s"

        queries = {
            "used_memory_bytes": f'redis_memory_used_bytes{{{inst}}}',
            "connected_clients": f'redis_connected_clients{{{inst}}}',
            "ops_per_sec": f'rate(redis_commands_processed_total{{{inst}}}[{rate_interval}])',
            "hit_ratio": (
                f'redis_keyspace_hits_total{{{inst}}} / '
                f'clamp_min(redis_keyspace_hits_total{{{inst}}} + '
                f'redis_keyspace_misses_total{{{inst}}}, 1) * 100'
            ),
            "evicted_keys": f'redis_evicted_keys_total{{{inst}}}',
        }

        return self._run_snapshot_queries(queries, start, end, step, source="redis_exporter")

    def get_mastodon_metrics(self, target, timeframe="day"):
        """Query Mastodon built-in Prometheus exporter metrics and return snapshots.

        Uses ruby_* prefixed metrics from the prometheus_exporter gem.
        Duration metrics are summaries (not histograms) so we compute averages via sum/count.
        """
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        inst = f'instance="{target}"'
        ri = f"{max(step * 2, 120)}s"

        # Helper for summary average: rate(sum) / rate(count)
        def _summary_avg(metric):
            return (
                f'sum(rate({metric}_sum{{{inst}}}[{ri}])) / '
                f'clamp_min(sum(rate({metric}_count{{{inst}}}[{ri}])), 1e-10)'
            )

        queries = {
            # -- Puma / Web --
            "puma_request_rate": f'sum(rate(ruby_http_requests{{{inst}}}[{ri}]))',
            "puma_avg_response_time": _summary_avg("ruby_http_request_duration_seconds"),
            "puma_sql_duration": _summary_avg("ruby_http_duration_sql_seconds"),
            "puma_redis_duration": _summary_avg("ruby_http_duration_redis_seconds"),
            "puma_queue_wait": _summary_avg("ruby_http_duration_queue_seconds"),
            "puma_thread_utilization": (
                f'sum(ruby_puma_running_threads{{{inst}}}) / '
                f'clamp_min(sum(ruby_puma_max_threads{{{inst}}}), 1) * 100'
            ),
            "puma_backlog": f'sum(ruby_puma_backlog{{{inst}}})',
            "puma_rss_memory": f'sum(ruby_rss{{{inst}}})',
            # -- Sidekiq --
            "sidekiq_throughput": f'sum(rate(ruby_sidekiq_jobs_total{{{inst}}}[{ri}]))',
            "sidekiq_failure_rate": f'sum(rate(ruby_sidekiq_failed_jobs_total{{{inst}}}[{ri}]))',
            "sidekiq_avg_duration": _summary_avg("ruby_sidekiq_job_duration_seconds"),
            "sidekiq_enqueued": f'sum(ruby_sidekiq_jobs_enqueued{{{inst}}})',
            "sidekiq_retry_queue": f'sum(ruby_sidekiq_restarted_jobs_total{{{inst}}})',
            "sidekiq_dead_queue": f'sum(ruby_sidekiq_dead_jobs_total{{{inst}}})',
            # -- ActiveRecord --
            "db_pool_utilization": (
                f'sum(ruby_active_record_connection_pool_busy{{{inst}}}) / '
                f'clamp_min(sum(ruby_active_record_connection_pool_size{{{inst}}}), 1) * 100'
            ),
            "db_pool_waiting": f'sum(ruby_active_record_connection_pool_waiting{{{inst}}})',
            # -- Ruby runtime --
            "ruby_gc_rate": f'sum(rate(ruby_gc_count{{{inst}}}[{ri}]))',
            "ruby_heap_live_slots": f'sum(ruby_heap_live_slots{{{inst}}})',
            "ruby_allocations_rate": f'sum(rate(ruby_allocations{{{inst}}}[{ri}]))',
        }

        return self._run_snapshot_queries(queries, start, end, step, source="mastodon_exporter")

    def get_jvb_metrics_exporter(self, target, timeframe="day"):
        """Query native JVB Prometheus metrics and return snapshots."""
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur
        inst = f'instance="{target}"'

        queries = {
            "conferences": f"jitsi_jvb_conferences{{{inst}}}",
            "participants": f"jitsi_jvb_participants{{{inst}}}",
            "stress_level": f"jitsi_jvb_stress_level{{{inst}}}",
            "bit_rate_download": f"jitsi_jvb_bit_rate_download{{{inst}}}",
            "bit_rate_upload": f"jitsi_jvb_bit_rate_upload{{{inst}}}",
            "conferences_created_total": f"jitsi_jvb_conferences_created_total{{{inst}}}",
            "participants_total": f"jitsi_jvb_participants_total{{{inst}}}",
            "ice_succeeded_total": f"jitsi_jvb_ice_succeeded_total{{{inst}}}",
            "ice_failed_total": f"jitsi_jvb_ice_failed_total{{{inst}}}",
        }

        return self._run_snapshot_queries(queries, start, end, step, source="jitsi_jvb")

    def _run_snapshot_queries(self, queries, start, end, step, source="exporter"):
        """Run multiple range queries and build a snapshot list."""
        all_series = {}
        timestamps = []

        for short_name, promql in queries.items():
            result = self._range_single(promql, start, end, step)
            all_series[short_name] = result.get("values", [])
            if not timestamps and result.get("timestamps"):
                timestamps = result["timestamps"]

        snapshots = []
        for i, ts in enumerate(timestamps):
            snap = {"captured_at": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()}
            for name, values in all_series.items():
                snap[name] = values[i] if i < len(values) else None
            snapshots.append(snap)

        return {"snapshots": snapshots, "source": source}

    # ----- internal -----

    def _range_single(self, promql, start, end, step):
        """Run a range query expecting a single time series and return timestamps + values."""
        try:
            results = self.query_range(promql, start, end, step)
        except Exception:
            logger.debug("Prometheus range query failed for %s", promql, exc_info=True)
            return {"timestamps": [], "values": []}

        if not results:
            return {"timestamps": [], "values": []}

        # Take the first matching series
        values_raw = results[0].get("values", [])
        timestamps = []
        values = []
        for ts, val in values_raw:
            timestamps.append(float(ts))
            try:
                values.append(round(float(val), 2))
            except (TypeError, ValueError):
                values.append(None)

        return {"timestamps": timestamps, "values": values}
