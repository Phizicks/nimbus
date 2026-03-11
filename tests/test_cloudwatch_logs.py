"""
CloudWatch Logs Unit Tests
Tests CloudWatch Logs functionality using AWS CLI commands through subprocess
Preserves exact command execution from original bash tests
"""

import unittest
import subprocess
import json
import os
import time


class TestCloudWatchLogs(unittest.TestCase):
    """CloudWatch Logs unit tests"""

    TEST_LOG_GROUP = "/test/cloudwatch/logs"

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures - Clean up previous artifacts first"""
        cls._cleanup_previous_artifacts()
        cls.test_log_stream = f"test-stream-{int(time.time())}"

    @classmethod
    def _cleanup_previous_artifacts(cls):
        """Clean up any leftover log groups from previous test runs"""
        subprocess.run([
            "aws", "logs", "delete-log-group",
            "--log-group-name", cls.TEST_LOG_GROUP,
            "--endpoint-url", "http://localhost:4566"
        ], capture_output=True)

    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests"""
        cls._cleanup_previous_artifacts()

    def run_command(self, cmd, check=True):
        """Run a shell command and return result"""
        if len(cmd) > 0 and cmd[0] == "aws" and "--endpoint-url" not in cmd:
            if len(cmd) > 1:
                insert_idx = 2
                cmd.insert(insert_idx, "--endpoint-url")
                cmd.insert(insert_idx + 1, "http://localhost:4566")

        result = subprocess.run(cmd, capture_output=True, text=True, env=os.environ.copy())
        if check and result.returncode != 0:
            self.fail(f"Command failed: {' '.join(cmd)}\nStderr: {result.stderr}")
        return result

    def test_01_create_log_group(self):
        """TEST 1: CreateLogGroup - Create a log group"""
        result = self.run_command([
            "aws", "logs", "create-log-group",
            "--log-group-name", self.TEST_LOG_GROUP
        ])
        self.assertEqual(result.returncode, 0)

    def test_02_create_duplicate_log_group_fails(self):
        """TEST 2: CreateLogGroup - Duplicate log group should fail"""
        result = self.run_command([
            "aws", "logs", "create-log-group",
            "--log-group-name", self.TEST_LOG_GROUP
        ], check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ResourceAlreadyExistsException", result.stderr + result.stdout)

    def test_03_describe_log_groups(self):
        """TEST 3: DescribeLogGroups - Describe log groups"""
        result = self.run_command([
            "aws", "logs", "describe-log-groups",
            "--log-group-name-prefix", self.TEST_LOG_GROUP,
            "--output", "json"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        group_names = [g["logGroupName"] for g in output["logGroups"]]
        self.assertIn(self.TEST_LOG_GROUP, group_names)

    def test_04_create_log_stream(self):
        """TEST 4: CreateLogStream - Create a log stream"""
        result = self.run_command([
            "aws", "logs", "create-log-stream",
            "--log-group-name", self.TEST_LOG_GROUP,
            "--log-stream-name", self.test_log_stream
        ])
        self.assertEqual(result.returncode, 0)

    def test_05_create_duplicate_log_stream_fails(self):
        """TEST 5: CreateLogStream - Duplicate log stream should fail"""
        result = self.run_command([
            "aws", "logs", "create-log-stream",
            "--log-group-name", self.TEST_LOG_GROUP,
            "--log-stream-name", self.test_log_stream
        ], check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_06_describe_log_streams(self):
        """TEST 6: DescribeLogStreams - Describe log streams"""
        result = self.run_command([
            "aws", "logs", "describe-log-streams",
            "--log-group-name", self.TEST_LOG_GROUP,
            "--output", "json"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        stream_names = [s["logStreamName"] for s in output["logStreams"]]
        self.assertIn(self.test_log_stream, stream_names)

    def test_07_put_log_events(self):
        """TEST 7: PutLogEvents - Put log events"""
        timestamp = int(time.time() * 1000)
        result = self.run_command([
            "aws", "logs", "put-log-events",
            "--log-group-name", self.TEST_LOG_GROUP,
            "--log-stream-name", self.test_log_stream,
            "--log-events",
            f"timestamp={timestamp},message=Test message 1",
            f"timestamp={timestamp + 1},message=Test message 2",
            f"timestamp={timestamp + 2},message=ERROR: Test error message",
            "--output", "json"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("nextSequenceToken", output)

    def test_08_get_log_events(self):
        """TEST 8: GetLogEvents - Get log events"""
        # Allow time for log indexing
        time.sleep(2)

        result = self.run_command([
            "aws", "logs", "get-log-events",
            "--log-group-name", self.TEST_LOG_GROUP,
            "--log-stream-name", self.test_log_stream,
            "--output", "json"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("events", output)
        self.assertGreaterEqual(len(output["events"]), 3,
                                f"Expected at least 3 events, found {len(output['events'])}")

    def test_09_get_log_events_with_time_range(self):
        """TEST 9: GetLogEvents - Get log events with time range"""
        start_time = int((time.time() - 3600) * 1000)  # 1 hour ago
        end_time = int(time.time() * 1000)

        result = self.run_command([
            "aws", "logs", "get-log-events",
            "--log-group-name", self.TEST_LOG_GROUP,
            "--log-stream-name", self.test_log_stream,
            "--start-time", str(start_time),
            "--end-time", str(end_time),
            "--output", "json"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertGreater(len(output["events"]), 0)

    def test_10_filter_log_events(self):
        """TEST 10: FilterLogEvents - Filter log events by pattern"""
        result = self.run_command([
            "aws", "logs", "filter-log-events",
            "--log-group-name", self.TEST_LOG_GROUP,
            "--filter-pattern", "ERROR",
            "--output", "json"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("events", output)
        self.assertGreaterEqual(len(output["events"]), 1,
                                "Expected at least 1 event matching 'ERROR'")

    def test_11_filter_log_events_specific_stream(self):
        """TEST 11: FilterLogEvents - Filter log events for specific stream"""
        result = self.run_command([
            "aws", "logs", "filter-log-events",
            "--log-group-name", self.TEST_LOG_GROUP,
            "--log-stream-names", self.test_log_stream,
            "--output", "json"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertGreater(len(output["events"]), 0)

    def test_12_delete_log_stream(self):
        """TEST 12: DeleteLogStream - Delete log stream"""
        result = self.run_command([
            "aws", "logs", "delete-log-stream",
            "--log-group-name", self.TEST_LOG_GROUP,
            "--log-stream-name", self.test_log_stream
        ])
        self.assertEqual(result.returncode, 0)

    def test_13_verify_log_stream_deleted(self):
        """TEST 13: Verify log stream deleted"""
        result = self.run_command([
            "aws", "logs", "describe-log-streams",
            "--log-group-name", self.TEST_LOG_GROUP,
            "--log-stream-name-prefix", self.test_log_stream,
            "--output", "json"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(len(output["logStreams"]), 0,
                         "Stream still exists after deletion")

    def test_14_delete_log_group(self):
        """TEST 14: DeleteLogGroup - Delete log group"""
        result = self.run_command([
            "aws", "logs", "delete-log-group",
            "--log-group-name", self.TEST_LOG_GROUP
        ])
        self.assertEqual(result.returncode, 0)

    def test_15_verify_log_group_deleted(self):
        """TEST 15: Verify log group deleted"""
        result = self.run_command([
            "aws", "logs", "describe-log-groups",
            "--log-group-name-prefix", self.TEST_LOG_GROUP,
            "--output", "json"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(len(output["logGroups"]), 0,
                         "Log group still exists after deletion")


if __name__ == "__main__":
    unittest.main(verbosity=2)
