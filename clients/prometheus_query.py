"""
Prometheus HTTP API query client.

Wraps the Prometheus ``/api/v1/query`` and ``/api/v1/query_range`` endpoints
to retrieve metrics data for display in Chart.js charts.  Falls back
gracefully when Prometheus is unreachable.
"""

import logging
import time
from datetime import datetime, timezone

import requests

from models import Setting

logger = logging.getLogger(__name__)

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

    def get_guest_rrd(self, vmid, timeframe="day"):
        """Query Prometheus for guest performance metrics and return Chart.js-ready JSON.

        Returns a dict matching the format of the existing guest_rrd() endpoint.
        """
        dur, step = _TIMEFRAMES.get(timeframe, _TIMEFRAMES["day"])
        end = time.time()
        start = end - dur

        vmid_str = str(vmid)

        cpu_data = self._range_single(f'lambnet_guest_cpu_usage_percent{{vmid="{vmid_str}"}}', start, end, step)
        mem_used = self._range_single(f'lambnet_guest_memory_used_bytes{{vmid="{vmid_str}"}}', start, end, step)
        mem_total = self._range_single(f'lambnet_guest_memory_total_bytes{{vmid="{vmid_str}"}}', start, end, step)
        netin = self._range_single(f'lambnet_guest_network_in_bytes_per_sec{{vmid="{vmid_str}"}}', start, end, step)
        netout = self._range_single(f'lambnet_guest_network_out_bytes_per_sec{{vmid="{vmid_str}"}}', start, end, step)

        # Build labels from the first dataset that has timestamps
        timestamps = cpu_data.get("timestamps") or mem_used.get("timestamps") or []
        labels = [datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M") for ts in timestamps]

        cpu_vals = cpu_data.get("values", [])
        mem_used_vals = mem_used.get("values", [])
        mem_total_vals = mem_total.get("values", [])
        netin_vals = netin.get("values", [])
        netout_vals = netout.get("values", [])

        # Compute mem_percent and mem_used_mb
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

        # Pick net unit
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
        labels = [datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M") for ts in timestamps]

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

        return {"snapshots": snapshots}

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
