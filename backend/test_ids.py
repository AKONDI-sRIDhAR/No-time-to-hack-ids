import unittest
from unittest.mock import patch, MagicMock, mock_open
import time
import ids
import json

class TestIDS(unittest.TestCase):
    def setUp(self):
        ids.known_devices = {}
        ids.device_stats = ids.defaultdict(lambda: {"ports": set(), "packets": 0})
        ids.START_TIME = time.time() - 10 # 10 seconds ago

    @patch("ids.subprocess.check_output")
    @patch("ids.open", new_callable=mock_open)
    @patch("ids.os.path.exists")
    def test_scan_network_state_wifi(self, mock_exists, _mock_file, mock_subprocess):
        # Mock file existence
        mock_exists.return_value = False

        # Mock iw output
        mock_subprocess.return_value = "Station AA:BB:CC:DD:EE:FF (on wlan0)"

        ids.scan_network_state()

        self.assertIn("AA:BB:CC:DD:EE:FF", ids.known_devices)
        self.assertEqual(ids.known_devices["AA:BB:CC:DD:EE:FF"]["ip"], "0.0.0.0")

    @patch("ids.subprocess.check_output")
    @patch("ids.os.path.exists")
    def test_scan_network_state_dhcp(self, mock_exists, mock_subprocess):
        # Mock file existence
        mock_exists.side_effect = lambda x: x == "/var/lib/misc/dnsmasq.leases"

        # Mock iw output (empty)
        mock_subprocess.return_value = ""

        expiry = int(time.time() + 3600)
        lease_content = f"{expiry} AA:BB:CC:DD:EE:FF 192.168.10.2 myphone *"

        with patch("ids.open", mock_open(read_data=lease_content)):
             ids.scan_network_state()

        self.assertIn("AA:BB:CC:DD:EE:FF", ids.known_devices)
        self.assertEqual(ids.known_devices["AA:BB:CC:DD:EE:FF"]["ip"], "192.168.10.2")
        self.assertEqual(ids.known_devices["AA:BB:CC:DD:EE:FF"]["hostname"], "myphone")

    @patch("ids.subprocess.check_output")
    @patch("ids.open", new_callable=mock_open)
    @patch("ids.os.path.exists")
    def test_scan_network_state_arp(self, mock_exists, _mock_file, mock_subprocess):
        mock_exists.return_value = False

        def side_effect(cmd, **kwargs):
            if cmd == ["ip", "neigh"]:
                return "192.168.10.3 dev wlan0 lladdr 11:22:33:44:55:66 REACHABLE"
            if cmd == ["iw", "dev", "wlan0", "station", "dump"]:
                return ""
            return ""

        mock_subprocess.side_effect = side_effect

        ids.scan_network_state()

        self.assertIn("11:22:33:44:55:66", ids.known_devices)
        self.assertEqual(ids.known_devices["11:22:33:44:55:66"]["ip"], "192.168.10.3")

    @patch("ids.scan_network_state")
    @patch("ids.is_anomalous")
    @patch("ids.log_event")
    @patch("ids.save_devices")
    def test_analyze_traffic_statuses(self, _mock_save, _mock_log, mock_anomalous, _mock_scan):
        # Setup known devices
        now = time.time()
        ids.known_devices = {
            "ONLINE_DEV": {
                "ip": "1.2.3.4", "mac": "ONLINE_DEV", "hostname": "h1",
                "first_seen": now, "last_seen": now, "trust_score": 50,
                "flags": {"redirected": False, "isolated": False, "quarantined": False}
            },
            "OFFLINE_DEV": {
                "ip": "1.2.3.5", "mac": "OFFLINE_DEV", "hostname": "h2",
                "first_seen": now - 100, "last_seen": now - 100, "trust_score": 50,
                "flags": {"redirected": False, "isolated": False, "quarantined": False}
            },
            "IDLE_DEV": {
                "ip": "1.2.3.6", "mac": "IDLE_DEV", "hostname": "h3",
                "first_seen": now, "last_seen": now, "trust_score": 50,
                "flags": {"redirected": False, "isolated": False, "quarantined": False}
            },
             "SUSPICIOUS_DEV": {
                "ip": "1.2.3.7", "mac": "SUSPICIOUS_DEV", "hostname": "h4",
                "first_seen": now, "last_seen": now, "trust_score": 80,
                "flags": {"redirected": False, "isolated": False, "quarantined": False}
            }
        }

        # ONLINE_DEV has traffic
        ids.device_stats["ONLINE_DEV"]["packets"] = 10
        ids.device_stats["ONLINE_DEV"]["ports"].add(80)

        # IDLE_DEV has NO traffic
        ids.device_stats["IDLE_DEV"]["packets"] = 0

        # SUSPICIOUS_DEV has traffic and anomalous
        # Rate > 50 needed. Duration is 10s. So packets > 500.
        ids.device_stats["SUSPICIOUS_DEV"]["packets"] = 600
        ids.device_stats["SUSPICIOUS_DEV"]["ports"].add(22)

        def anomalous_side_effect(rate, _ports):
            if rate > 50:
                return True, "100 Anomalous"
            return False, "0 Normal"
        mock_anomalous.side_effect = anomalous_side_effect

        _threats, active = ids.analyze_traffic()

        status_map = {d["mac"]: d["status"] for d in active}

        self.assertEqual(status_map["ONLINE_DEV"], "ONLINE")
        self.assertEqual(status_map["OFFLINE_DEV"], "OFFLINE")
        self.assertEqual(status_map["IDLE_DEV"], "IDLE")
        self.assertEqual(status_map["SUSPICIOUS_DEV"], "SUSPICIOUS")

if __name__ == "__main__":
    unittest.main()
