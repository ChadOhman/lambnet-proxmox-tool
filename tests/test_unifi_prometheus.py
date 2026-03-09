"""Tests for UniFi Prometheus metrics (clients/prometheus_exporter.py)."""

from clients.prometheus_exporter import (
    get_metrics,
    update_unifi_device_metrics,
    update_unifi_health_metrics,
    update_unifi_metrics,
)


class TestUpdateUnifiDeviceMetrics:
    def test_sets_device_gauges(self):
        devices = [{
            "name": "AP-01",
            "mac": "aa:bb:cc:dd:ee:ff",
            "type": "uap",
            "cpu": 15.0,
            "mem": 42.0,
            "uptime": 86400,
            "temperature": 55.0,
            "loadavg_1": 0.5,
            "num_sta": 5,
            "uplink": {"speed": 1000, "tx_bytes": 1000000, "rx_bytes": 2000000},
            "radio_table": [
                {"name": "ra0", "channel": 36, "cu_total": 20, "num_sta": 5, "tx_power": 23},
            ],
        }]
        update_unifi_device_metrics("default", devices)

        output = get_metrics().decode()
        assert 'mstdnca_unifi_device_cpu_percent{device_mac="aa:bb:cc:dd:ee:ff"' in output
        assert 'mstdnca_unifi_device_memory_percent{device_mac="aa:bb:cc:dd:ee:ff"' in output
        assert 'mstdnca_unifi_device_uptime_seconds{device_mac="aa:bb:cc:dd:ee:ff"' in output
        assert 'mstdnca_unifi_device_temperature_celsius{device_mac="aa:bb:cc:dd:ee:ff"' in output
        assert 'mstdnca_unifi_device_clients{device_mac="aa:bb:cc:dd:ee:ff"' in output
        assert 'mstdnca_unifi_radio_channel{' in output
        assert 'mstdnca_unifi_radio_channel_utilization{' in output

    def test_handles_missing_fields(self):
        devices = [{"name": "Switch", "mac": "11:22:33:44:55:66", "type": "usw",
                     "uplink": {}, "radio_table": []}]
        # Should not raise
        update_unifi_device_metrics("default", devices)

    def test_empty_devices(self):
        # Should not raise
        update_unifi_device_metrics("default", [])


class TestUpdateUnifiHealthMetrics:
    def test_sets_health_gauges(self):
        health_data = [
            {
                "subsystem": "wan",
                "status": "ok",
                "latency": 5,
                "tx_bytes-r": 50000,
                "rx_bytes-r": 100000,
                "uptime": 86400,
                "speedtest_lastrun_download": 100.5,
                "speedtest_lastrun_upload": 20.3,
            },
            {"subsystem": "lan", "status": "ok"},
            {"subsystem": "wlan", "status": "ok"},
        ]
        update_unifi_health_metrics("default", health_data)

        output = get_metrics().decode()
        assert 'mstdnca_unifi_health_status{site_name="default",subsystem="wan"} 1.0' in output
        assert 'mstdnca_unifi_health_status{site_name="default",subsystem="lan"} 1.0' in output
        assert 'mstdnca_unifi_wan_latency_ms{site_name="default"} 5.0' in output
        assert 'mstdnca_unifi_speedtest_download_mbps{site_name="default"} 100.5' in output
        assert 'mstdnca_unifi_speedtest_upload_mbps{site_name="default"} 20.3' in output

    def test_warning_status(self):
        update_unifi_health_metrics("test", [{"subsystem": "wan", "status": "warning"}])
        output = get_metrics().decode()
        assert 'mstdnca_unifi_health_status{site_name="test",subsystem="wan"} 2.0' in output

    def test_unknown_status(self):
        update_unifi_health_metrics("test2", [{"subsystem": "vpn", "status": "something_else"}])
        output = get_metrics().decode()
        assert 'mstdnca_unifi_health_status{site_name="test2",subsystem="vpn"} 0.0' in output

    def test_empty_health_data(self):
        # Should not raise
        update_unifi_health_metrics("default", [])

    def test_skips_missing_subsystem(self):
        # Entry without subsystem key should be skipped
        update_unifi_health_metrics("default", [{"status": "ok"}])


class TestUpdateUnifiMetrics:
    def test_aggregate_metrics(self):
        update_unifi_metrics("default", device_count=5, client_count=20)
        output = get_metrics().decode()
        assert 'mstdnca_unifi_device_count{site_name="default"} 5.0' in output
        assert 'mstdnca_unifi_client_count{site_name="default"} 20.0' in output
