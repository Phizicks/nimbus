"""
Event Source Mapping Unit Tests
Tests Lambda Event Source Mapping (ESM) functionality using AWS CLI commands through subprocess
Preserves exact command execution from original bash tests
"""

import unittest
import subprocess
import json
import os
import time
import zipfile
import tempfile


class TestEventSourceMapping(unittest.TestCase):
    """Event Source Mapping unit tests"""

    LAMBDA_NAME = "esm-lambda-test"
    SOURCE_QUEUE_NAME = "esm-basic-queue"
    RESULT_QUEUE_NAME = "esm-result-queue"

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures - Clean up previous artifacts first"""
        cls._cleanup_previous_artifacts()
        cls.temp_dir = tempfile.mkdtemp()
        cls.source_queue_url = None
        cls.result_queue_url = None
        cls.esm_uuid = None

    @classmethod
    def _cleanup_previous_artifacts(cls):
        """Clean up any leftover resources from previous test runs"""
        # Delete event source mappings
        result = subprocess.run([
            "aws", "lambda", "list-event-source-mappings",
            "--function-name", cls.LAMBDA_NAME,
            "--endpoint-url", "http://localhost:4566"
        ], capture_output=True, text=True)

        if result.returncode == 0:
            try:
                output = json.loads(result.stdout)
                for mapping in output.get("EventSourceMappings", []):
                    subprocess.run([
                        "aws", "lambda", "delete-event-source-mapping",
                        "--uuid", mapping["UUID"],
                        "--endpoint-url", "http://localhost:4566"
                    ], capture_output=True)
            except json.JSONDecodeError:
                pass

        # Delete lambda function
        subprocess.run([
            "aws", "lambda", "delete-function",
            "--function-name", cls.LAMBDA_NAME,
            "--endpoint-url", "http://localhost:4566"
        ], capture_output=True)

        # Delete queues
        for queue_name in [cls.SOURCE_QUEUE_NAME, cls.RESULT_QUEUE_NAME]:
            queue_url = f"http://localhost:9324/456645664566/{queue_name}"
            subprocess.run([
                "aws", "sqs", "delete-queue",
                "--queue-url", queue_url,
                "--endpoint-url", "http://localhost:4566"
            ], capture_output=True)

    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests"""
        cls._cleanup_previous_artifacts()
        # Clean up temp files
        for f in os.listdir(cls.temp_dir):
            try:
                os.remove(os.path.join(cls.temp_dir, f))
            except OSError:
                pass
        try:
            os.rmdir(cls.temp_dir)
        except OSError:
            pass

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

    def test_01_create_source_queue(self):
        """TEST 1: Create SQS source queue for ESM"""
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", self.SOURCE_QUEUE_NAME,
            "--attributes", "VisibilityTimeout=2,MessageRetentionPeriod=300"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        TestEventSourceMapping.source_queue_url = output["QueueUrl"]

    def test_02_create_result_queue(self):
        """TEST 2: Create SQS result queue for ESM"""
        result = self.run_command([
            "aws", "sqs", "create-queue",
            "--queue-name", self.RESULT_QUEUE_NAME,
            "--attributes", "VisibilityTimeout=2,MessageRetentionPeriod=300"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        TestEventSourceMapping.result_queue_url = output["QueueUrl"]

    def test_03_create_lambda_function(self):
        """TEST 3: Create Lambda function for ESM processing"""
        # Create a simple forwarding Lambda function
        handler_code = """
const { SQSClient, SendMessageCommand } = require("@aws-sdk/client-sqs");

exports.handler = async (event) => {
    const sqsClient = new SQSClient({
        endpoint: process.env.AWS_ENDPOINT_URL_SQS || "http://api:4566"
    });

    for (const record of event.Records) {
        await sqsClient.send(new SendMessageCommand({
            QueueUrl: process.env.RESULT_QUEUE_URL,
            MessageBody: record.body
        }));
    }

    return { statusCode: 200 };
};
"""
        handler_file = os.path.join(self.temp_dir, "events.js")
        with open(handler_file, "w") as f:
            f.write(handler_code)

        zip_file = os.path.join(self.temp_dir, "function.zip")
        with zipfile.ZipFile(zip_file, "w") as zf:
            zf.write(handler_file, arcname="events.js")

        result = self.run_command([
            "aws", "lambda", "create-function",
            "--function-name", self.LAMBDA_NAME,
            "--runtime", "nodejs22.x",
            "--handler", "events.handler",
            "--role", "arn:aws:iam::456645664566:role/nodejs-role",
            "--zip-file", f"fileb://{zip_file}",
            "--environment", f"Variables={{RESULT_QUEUE_URL={self.result_queue_url},AWS_ENDPOINT_URL_SQS=http://api:4566}}"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["FunctionName"], self.LAMBDA_NAME)

    def test_04_get_source_queue_arn(self):
        """TEST 4: Get source queue ARN"""
        result = self.run_command([
            "aws", "sqs", "get-queue-attributes",
            "--queue-url", self.source_queue_url,
            "--attribute-names", "QueueArn"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Attributes", output)
        self.assertIn("QueueArn", output["Attributes"])

    def test_05_create_event_source_mapping(self):
        """TEST 5: CreateEventSourceMapping - Create ESM from SQS to Lambda"""
        # Get source queue ARN
        result = self.run_command([
            "aws", "sqs", "get-queue-attributes",
            "--queue-url", self.source_queue_url,
            "--attribute-names", "QueueArn"
        ])
        queue_arn = json.loads(result.stdout)["Attributes"]["QueueArn"]

        result = self.run_command([
            "aws", "lambda", "create-event-source-mapping",
            "--event-source-arn", queue_arn,
            "--function-name", self.LAMBDA_NAME,
            "--batch-size", "1",
            "--enabled"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("UUID", output)
        TestEventSourceMapping.esm_uuid = output["UUID"]

    def test_06_list_event_source_mappings(self):
        """TEST 6: ListEventSourceMappings - List ESMs for function"""
        result = self.run_command([
            "aws", "lambda", "list-event-source-mappings",
            "--function-name", self.LAMBDA_NAME
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("EventSourceMappings", output)
        self.assertGreater(len(output["EventSourceMappings"]), 0)

    def test_07_get_event_source_mapping(self):
        """TEST 7: GetEventSourceMapping - Get specific ESM"""
        result = self.run_command([
            "aws", "lambda", "get-event-source-mapping",
            "--uuid", self.esm_uuid
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["UUID"], self.esm_uuid)
        self.assertEqual(output["FunctionArn"],
                         f"arn:aws:lambda:ap-southeast-2:456645664566:function:{self.LAMBDA_NAME}")

    def test_08_send_message_and_verify_processing(self):
        """TEST 8: End-to-end - Send message to source queue, verify Lambda processes it"""
        # Wait for ESM to be active
        time.sleep(5)

        # Send test message
        self.run_command([
            "aws", "sqs", "send-message",
            "--queue-url", self.source_queue_url,
            "--message-body", "Hello EMS Lambda"
        ])

        # Wait and poll result queue
        received = False
        for i in range(10):
            result = self.run_command([
                "aws", "sqs", "receive-message",
                "--queue-url", self.result_queue_url,
                "--max-number-of-messages", "1",
                "--wait-time-seconds", "1"
            ], check=False)

            if result.returncode == 0 and result.stdout.strip():
                try:
                    output = json.loads(result.stdout)
                    messages = output.get("Messages", [])
                    if messages and messages[0].get("Body") == "Hello EMS Lambda":
                        received = True
                        # Delete the message
                        self.run_command([
                            "aws", "sqs", "delete-message",
                            "--queue-url", self.result_queue_url,
                            "--receipt-handle", messages[0]["ReceiptHandle"]
                        ], check=False)
                        break
                except json.JSONDecodeError:
                    pass
            time.sleep(1)

        self.assertTrue(received, "No matching message received in result queue after ESM processing")

    def test_09_update_event_source_mapping(self):
        """TEST 9: UpdateEventSourceMapping - Disable ESM"""
        result = self.run_command([
            "aws", "lambda", "update-event-source-mapping",
            "--uuid", self.esm_uuid,
            "--no-enabled"
        ])
        self.assertEqual(result.returncode, 0)

    def test_10_delete_event_source_mapping(self):
        """TEST 10: DeleteEventSourceMapping - Delete ESM"""
        result = self.run_command([
            "aws", "lambda", "delete-event-source-mapping",
            "--uuid", self.esm_uuid
        ])
        self.assertEqual(result.returncode, 0)

    def test_11_verify_esm_deleted(self):
        """TEST 11: Verify ESM is deleted"""
        result = self.run_command([
            "aws", "lambda", "list-event-source-mappings",
            "--function-name", self.LAMBDA_NAME
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        uuids = [m["UUID"] for m in output.get("EventSourceMappings", [])]
        self.assertNotIn(self.esm_uuid, uuids)


if __name__ == "__main__":
    unittest.main(verbosity=2)
