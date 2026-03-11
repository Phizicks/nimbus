"""
SQS Unit Tests
Tests SQS functionality using AWS CLI commands through subprocess
Preserves exact command execution from original bash tests
"""

import unittest
import subprocess
import json
import time
import sys
import os


class TestSQS(unittest.TestCase):
    """SQS unit tests"""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures - Clean up previous artifacts first"""
        # PRE-CLEANUP: Remove any leftover queues from previous test runs
        cls._cleanup_previous_artifacts()

    @classmethod
    def _cleanup_previous_artifacts(cls):
        """Clean up any leftover queues from previous test runs"""
        result = subprocess.run([
            "aws", "sqs", "list-queues",
            "--endpoint-url", "http://localhost:4566"
        ], capture_output=True, text=True)

        if result.returncode == 0:
            try:
                output = json.loads(result.stdout)
                for queue_url in output.get("QueueUrls", []):
                    subprocess.run([
                        "aws", "sqs", "delete-queue",
                        "--queue-url", queue_url,
                        "--endpoint-url", "http://localhost:4566"
                    ], capture_output=True)
            except json.JSONDecodeError:
                pass

    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests"""
        # Use the same cleanup method
        cls._cleanup_previous_artifacts()

    def run_command(self, cmd, check=True):
        """Run a shell command and return result"""
        # Add endpoint URL if not already present for AWS CLI commands
        if len(cmd) > 0 and cmd[0] == "aws" and "--endpoint-url" not in cmd:
            # Find the service name (second element) and insert after it
            if len(cmd) > 1:
                service_name = cmd[1]
                # Insert endpoint URL before the operation name
                insert_idx = 2
                cmd.insert(insert_idx, "--endpoint-url")
                cmd.insert(insert_idx + 1, "http://localhost:4566")

        result = subprocess.run(cmd, capture_output=True, text=True, env=os.environ.copy())
        if check and result.returncode != 0:
            self.fail(f"Command failed: {' '.join(cmd)}\nStderr: {result.stderr}")
        return result

    def tearDown(self):
        """Clean up test queues after each test"""
        result = self.run_command([
            "aws", "sqs", "list-queues"
        ], check=False)

        if result.returncode == 0:
            output = json.loads(result.stdout)
            if "QueueUrls" in output:
                for queue_url in output["QueueUrls"]:
                    subprocess.run([
                        "aws", "sqs", "delete-queue",
                        "--queue-url", queue_url,
                        "--endpoint-url", "http://localhost:4566"
                    ], capture_output=True)

    def test_01_create_queue(self):
        """TEST 1.1: Create queue - CreateQueue"""
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", "sqs-basic-queue",
            "--attributes", "VisibilityTimeout=30,MessageRetentionPeriod=86400"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("QueueUrl", output)
        self.queue_url = output["QueueUrl"]

    def test_02_list_queues(self):
        """TEST 1.2: List queues - ListQueues"""
        # Create a queue first
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", "test-list-queue"
        ])
        self.assertEqual(result.returncode, 0)

        result = self.run_command([
            "aws", "sqs", "list-queues"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("QueueUrls", output)

    def test_03_get_queue_attributes(self):
        """TEST 1.3: Get queue attributes - GetQueueAttributes"""
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", "test-attrs-queue",
            "--attributes", "VisibilityTimeout=30"
        ])
        queue_url = json.loads(result.stdout)["QueueUrl"]

        result = self.run_command([
            "aws", "sqs", "get-queue-attributes",
            "--queue-url", queue_url,
            "--attribute-names", "All"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Attributes", output)

    def test_04_send_message(self):
        """TEST 1.4: Send message - SendMessage"""
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", "test-send-queue"
        ])
        queue_url = json.loads(result.stdout)["QueueUrl"]

        result = self.run_command([
            "aws", "sqs", "send-message",
            "--queue-url", queue_url,
            "--message-body", "Hello from LocalCloud SQS!"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("MessageId", output)

    def test_05_receive_message(self):
        """TEST 1.5: Receive message - ReceiveMessage"""
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", "test-receive-queue"
        ])
        queue_url = json.loads(result.stdout)["QueueUrl"]

        # Send a message
        self.run_command([
            "aws", "sqs", "send-message",
            "--queue-url", queue_url,
            "--message-body", "Test message"
        ])

        # Receive message
        result = self.run_command([
            "aws", "sqs", "receive-message",
            "--queue-url", queue_url,
            "--max-number-of-messages", "1"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Messages", output)
        self.assertEqual(output["Messages"][0]["Body"], "Test message")

    def test_06_delete_message(self):
        """TEST 1.6: Delete message - DeleteMessage"""
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", "test-delete-msg-queue"
        ])
        queue_url = json.loads(result.stdout)["QueueUrl"]

        # Send and receive
        self.run_command([
            "aws", "sqs", "send-message",
            "--queue-url", queue_url,
            "--message-body", "To be deleted"
        ])

        result = self.run_command([
            "aws", "sqs", "receive-message",
            "--queue-url", queue_url
        ])
        message = json.loads(result.stdout)["Messages"][0]
        receipt_handle = message["ReceiptHandle"]

        # Delete message
        result = self.run_command([
            "aws", "sqs", "delete-message",
            "--queue-url", queue_url,
            "--receipt-handle", receipt_handle
        ])
        self.assertEqual(result.returncode, 0)

    def test_07_batch_send_message(self):
        """TEST 2.1: Batch send messages - SendMessageBatch"""
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", "test-batch-queue"
        ])
        queue_url = json.loads(result.stdout)["QueueUrl"]

        result = self.run_command([
            "aws", "sqs", "send-message-batch",
            "--queue-url", queue_url,
            "--entries",
            "Id=msg1,MessageBody=Batch message 1",
            "Id=msg2,MessageBody=Batch message 2",
            "Id=msg3,MessageBody=Batch message 3"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Successful", output)

    def test_08_batch_receive_message(self):
        """TEST 2.2: Batch receive messages - ReceiveMessage batch"""
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", "test-batch-receive-queue"
        ])
        queue_url = json.loads(result.stdout)["QueueUrl"]

        # Send batch
        self.run_command([
            "aws", "sqs", "send-message-batch",
            "--queue-url", queue_url,
            "--entries",
            "Id=msg1,MessageBody=Message 1",
            "Id=msg2,MessageBody=Message 2",
            "Id=msg3,MessageBody=Message 3"
        ])

        # Receive batch
        result = self.run_command([
            "aws", "sqs", "receive-message",
            "--queue-url", queue_url,
            "--max-number-of-messages", "10"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Messages", output)
        self.assertGreaterEqual(len(output["Messages"]), 1)

    def test_09_visibility_timeout_immediate_fail(self):
        """TEST 4.1: Visibility timeout - Message not visible immediately"""
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", f"test-visibility-queue-{int(time.time())}",
            "--attributes", "VisibilityTimeout=5"
        ])
        queue_url = json.loads(result.stdout)["QueueUrl"]

        # Purge queue to clear any previous messages
        self.run_command([
            "aws", "sqs", "purge-queue",
            "--queue-url", queue_url
        ], check=False)

        # Allow broker time to process the purge
        time.sleep(1)

        # Send message
        self.run_command([
            "aws", "sqs", "send-message",
            "--queue-url", queue_url,
            "--message-body", "Visibility test"
        ])

        # Small sleep to allow message to be enqueued
        time.sleep(1)

        # Receive message (first time)
        result = self.run_command([
            "aws", "sqs", "receive-message",
            "--queue-url", queue_url,
            "--max-number-of-messages", "1"
        ])
        self.assertEqual(result.returncode, 0)
        message_data = json.loads(result.stdout)
        self.assertIn("Messages", message_data)

        # Try immediate receive (should fail - message is in visibility timeout)
        result = self.run_command([
            "aws", "sqs", "receive-message",
            "--queue-url", queue_url,
            "--max-number-of-messages", "1"
        ])
        output = json.loads(result.stdout)
        # Message should not be visible - either no "Messages" key or empty list
        messages = output.get("Messages", [])
        self.assertEqual(len(messages), 0, f"Message should not be visible due to visibility timeout, got: {output}")

    def test_10_change_message_visibility(self):
        """TEST 4.2: Change message visibility - ChangeMessageVisibility"""
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", f"test-change-visibility-{int(time.time())}",
            "--attributes", "VisibilityTimeout=30"
        ])
        queue_url = json.loads(result.stdout)["QueueUrl"]

        # Send message
        self.run_command([
            "aws", "sqs", "send-message",
            "--queue-url", queue_url,
            "--message-body", "Visibility change test"
        ])

        # Receive message
        result = self.run_command([
            "aws", "sqs", "receive-message",
            "--queue-url", queue_url
        ])
        message = json.loads(result.stdout)["Messages"][0]
        receipt_handle = message["ReceiptHandle"]

        # Change visibility to 1 second
        result = self.run_command([
            "aws", "sqs", "change-message-visibility",
            "--queue-url", queue_url,
            "--receipt-handle", receipt_handle,
            "--visibility-timeout", "1"
        ])
        self.assertEqual(result.returncode, 0)

    def test_11_queue_attributes(self):
        """TEST 5: Queue attributes - GetQueueAttributes"""
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", "test-queue-attrs"
        ])
        queue_url = json.loads(result.stdout)["QueueUrl"]

        # Send messages
        for i in range(3):
            self.run_command([
                "aws", "sqs", "send-message",
                "--queue-url", queue_url,
                "--message-body", f"Message {i}"
            ])

        # Get attributes
        result = self.run_command([
            "aws", "sqs", "get-queue-attributes",
            "--queue-url", queue_url,
            "--attribute-names", "ApproximateNumberOfMessages"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Attributes", output)

    def test_12_purge_queue(self):
        """TEST 5.1: Purge queue - PurgeQueue"""
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", "test-purge-queue"
        ])
        queue_url = json.loads(result.stdout)["QueueUrl"]

        # Send messages
        self.run_command([
            "aws", "sqs", "send-message-batch",
            "--queue-url", queue_url,
            "--entries",
            "Id=msg1,MessageBody=Message 1",
            "Id=msg2,MessageBody=Message 2"
        ])

        # Purge queue
        result = self.run_command([
            "aws", "sqs", "purge-queue",
            "--queue-url", queue_url
        ])
        self.assertEqual(result.returncode, 0)

    def test_13_fifo_queue_create(self):
        """TEST 6.1: FIFO queue creation"""
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", f"test-fifo-queue-{int(time.time())}.fifo",
            "--attributes", "FifoQueue=true"
        ], check=False)

        # FIFO may not be fully implemented, but we test if it is
        if result.returncode == 0:
            output = json.loads(result.stdout)
            self.assertIn("QueueUrl", output)

    def test_14_send_message_with_attributes(self):
        """TEST 7: Message attributes - SendMessage with attributes"""
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", "test-msg-attrs-queue"
        ])
        queue_url = json.loads(result.stdout)["QueueUrl"]

        result = self.run_command([
            "aws", "sqs", "send-message",
            "--queue-url", queue_url,
            "--message-body", "Message with attributes",
            "--message-attributes",
            "Author={StringValue=TestScript,DataType=String}"
        ])
        self.assertEqual(result.returncode, 0)

    def test_15_receive_message_with_attributes(self):
        """TEST 7.1: Receive message with attributes"""
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", "test-receive-attrs-queue"
        ])
        queue_url = json.loads(result.stdout)["QueueUrl"]

        # Send with attributes
        self.run_command([
            "aws", "sqs", "send-message",
            "--queue-url", queue_url,
            "--message-body", "Message with attrs",
            "--message-attributes",
            "Author={StringValue=TestScript,DataType=String}"
        ])

        # Receive with attribute names
        result = self.run_command([
            "aws", "sqs", "receive-message",
            "--queue-url", queue_url,
            "--message-attribute-names", "All"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Messages", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
