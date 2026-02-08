import unittest
from unittest.mock import patch
import response
import subprocess

class TestResponse(unittest.TestCase):

    def test_validate_ip_valid(self):
        try:
            response.validate_ip("192.168.1.1")
            response.validate_ip("10.0.0.1")
        except ValueError:
            self.fail("validate_ip raised ValueError unexpectedly!")

    def test_validate_ip_invalid(self):
        with self.assertRaises(ValueError):
            response.validate_ip("256.256.256.256")
        with self.assertRaises(ValueError):
            response.validate_ip("abc.def.ghi.jkl")
        with self.assertRaises(ValueError):
            response.validate_ip("192.168.1.1/24") # CIDR not allowed

    def test_validate_ip_loopback(self):
        with self.assertRaises(ValueError):
            response.validate_ip("127.0.0.1")

    @patch("response.subprocess.run")
    def test_run_cmd_success(self, mock_run):
        mock_run.return_value.returncode = 0
        self.assertTrue(response.run_cmd(["ls", "-la"]))

    @patch("response.subprocess.run")
    def test_run_cmd_failure(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "Error"
        self.assertFalse(response.run_cmd(["ls", "-la"]))

    @patch("response.subprocess.run")
    def test_run_cmd_ignore_error(self, mock_run):
        mock_run.return_value.returncode = 1
        self.assertTrue(response.run_cmd(["ls", "-la"], ignore_error=True))

if __name__ == "__main__":
    unittest.main()
