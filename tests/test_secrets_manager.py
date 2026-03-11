"""
Secrets Manager Unit Tests
Tests Secrets Manager functionality using AWS CLI commands through subprocess
Preserves exact command execution from original bash tests
"""

import unittest
import subprocess
import json
import base64
import os
import time
import tempfile


class TestSecretsManager(unittest.TestCase):
    """Secrets Manager unit tests"""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures - Clean up previous artifacts first"""
        # PRE-CLEANUP: Remove any leftover secrets from previous test runs
        cls._cleanup_previous_artifacts()

        cls.secret_name = "test-secret"
        cls.secret_value = "my-test-password-123"
        cls.updated_value = "my-updated-password-456"
        cls.version_id_testing = None
        cls.json_secret_value = '{"username":"admin","password":"secret123"}'
        cls.binary_secret_value = "binary-data-content"
        cls.temp_dir = tempfile.mkdtemp()

    @classmethod
    def _cleanup_previous_artifacts(cls):
        """Clean up any leftover secrets from previous test runs"""
        # List all secrets and delete those matching our test pattern
        result = subprocess.run([
            "aws", "secretsmanager", "list-secrets",
            "--endpoint-url", "http://localhost:4566"
        ], capture_output=True, text=True)

        if result.returncode == 0:
            try:
                output = json.loads(result.stdout)
                for secret in output.get("SecretList", []):
                    secret_name = secret.get("Name", "")
                    # Delete secrets matching our test patterns
                    if any(pattern in secret_name for pattern in ["test-secret", "duplicate-test"]):
                        subprocess.run([
                            "aws", "secretsmanager", "delete-secret",
                            "--secret-id", secret_name,
                            "--force-delete",
                            "--endpoint-url", "http://localhost:4566"
                        ], capture_output=True)
            except json.JSONDecodeError:
                pass

    @classmethod
    def tearDownClass(cls):
        """Clean up test fixtures"""
        # Use the same cleanup method as pre-test
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

    def test_01_create_secret_string(self):
        """TEST 1: CreateSecret - Create secret with string value"""
        result = self.run_command([
            "aws", "secretsmanager", "create-secret",
            "--name", self.secret_name,
            "--secret-string", self.secret_value,
            "--description", "Test secret for unit testing",
            "--tags", "Key=Environment,Value=test", "Key=Purpose,Value=unittest"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("ARN", output)
        self.assertIn("Name", output)

    def test_02_get_secret_value(self):
        """TEST 2: GetSecretValue - Get secret value"""
        result = self.run_command([
            "aws", "secretsmanager", "get-secret-value",
            "--secret-id", self.secret_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["SecretString"], self.secret_value)

    def test_03_describe_secret(self):
        """TEST 3: DescribeSecret - Describe secret metadata"""
        result = self.run_command([
            "aws", "secretsmanager", "describe-secret",
            "--secret-id", self.secret_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn(self.secret_name, output["ARN"])
        self.assertEqual(output["Description"], "Test secret for unit testing")

    def test_04_list_secrets(self):
        """TEST 4: ListSecrets - List all secrets"""
        result = self.run_command([
            "aws", "secretsmanager", "list-secrets"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("SecretList", output)
        secret_names = [s["Name"] for s in output["SecretList"]]
        self.assertIn(self.secret_name, secret_names)

    def test_05_update_secret(self):
        """TEST 5: UpdateSecret - Update secret value"""
        result = self.run_command([
            "aws", "secretsmanager", "update-secret",
            "--secret-id", self.secret_name,
            "--secret-string", self.updated_value,
            "--description", "Updated test secret"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("VersionId", output)

    def test_06_get_updated_secret(self):
        """TEST 6: GetSecretValue - Get updated secret value"""
        result = self.run_command([
            "aws", "secretsmanager", "get-secret-value",
            "--secret-id", self.secret_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["SecretString"], self.updated_value)

    def test_07_list_secret_version_ids(self):
        """TEST 7: ListSecretVersionIds - List secret versions"""
        result = self.run_command([
            "aws", "secretsmanager", "list-secret-version-ids",
            "--secret-id", self.secret_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Versions", output)
        self.assertGreater(len(output["Versions"]), 0)

    def test_08_get_previous_version(self):
        """TEST 8: GetSecretValue - Get previous version"""
        result = self.run_command([
            "aws", "secretsmanager", "get-secret-value",
            "--secret-id", self.secret_name,
            "--version-stage", "AWSPREVIOUS"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["SecretString"], self.secret_value)

    def test_09_create_json_secret(self):
        """TEST 9: CreateSecret - Create secret with JSON value"""
        result = self.run_command([
            "aws", "secretsmanager", "create-secret",
            "--name", f"{self.secret_name}-json",
            "--secret-string", self.json_secret_value
        ])
        self.assertEqual(result.returncode, 0)

    def test_10_get_json_secret(self):
        """TEST 10: GetSecretValue - Get JSON secret"""
        result = self.run_command([
            "aws", "secretsmanager", "get-secret-value",
            "--secret-id", f"{self.secret_name}-json"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        secret_json = json.loads(output["SecretString"])
        self.assertEqual(secret_json["username"], "admin")
        self.assertEqual(secret_json["password"], "secret123")

    def test_11_put_secret_value(self):
        """TEST 11: PutSecretValue - Put new version with stage"""
        result = self.run_command([
            "aws", "secretsmanager", "put-secret-value",
            "--secret-id", self.secret_name,
            "--secret-string", "third-version-value",
            "--version-stages", "TESTING"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("VersionId", output)
        TestSecretsManager.version_id_testing = output["VersionId"]

    def test_12_get_specific_version(self):
        """TEST 12: GetSecretValue - Get specific version by ID"""
        result = self.run_command([
            "aws", "secretsmanager", "get-secret-value",
            "--secret-id", self.secret_name,
            "--version-id", self.version_id_testing
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["SecretString"], "third-version-value")

    def test_13_update_secret_version_stage(self):
        """TEST 13: UpdateSecretVersionStage - Move version stage"""
        result = self.run_command([
            "aws", "secretsmanager", "update-secret-version-stage",
            "--secret-id", self.secret_name,
            "--version-stage", "AWSCURRENT",
            "--move-to-version-id", self.version_id_testing
        ])
        self.assertEqual(result.returncode, 0)

    def test_14_verify_current_version_updated(self):
        """TEST 14: GetSecretValue - Verify AWSCURRENT moved"""
        result = self.run_command([
            "aws", "secretsmanager", "get-secret-value",
            "--secret-id", self.secret_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["SecretString"], "third-version-value")

    def test_15_put_resource_policy(self):
        """TEST 15: PutResourcePolicy - Put resource policy"""
        policy_document = """{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {
            "AWS": "arn:aws:iam::123456789012:role/test-role"
        },
        "Action": "secretsmanager:GetSecretValue",
        "Resource": "*"
    }]
}"""
        result = self.run_command([
            "aws", "secretsmanager", "put-resource-policy",
            "--secret-id", self.secret_name,
            "--resource-policy", policy_document
        ])
        self.assertEqual(result.returncode, 0)

    def test_16_get_resource_policy(self):
        """TEST 16: GetResourcePolicy - Get resource policy"""
        result = self.run_command([
            "aws", "secretsmanager", "get-resource-policy",
            "--secret-id", self.secret_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("secretsmanager:GetSecretValue", output["ResourcePolicy"])

    def test_17_delete_resource_policy(self):
        """TEST 17: DeleteResourcePolicy - Delete resource policy"""
        result = self.run_command([
            "aws", "secretsmanager", "delete-resource-policy",
            "--secret-id", self.secret_name
        ])
        self.assertEqual(result.returncode, 0)

    def test_18_schedule_secret_deletion(self):
        """TEST 18: DeleteSecret - Schedule deletion"""
        result = self.run_command([
            "aws", "secretsmanager", "delete-secret",
            "--secret-id", self.secret_name,
            "--recovery-window-in-days", "7"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("DeletionDate", output)

    def test_19_describe_deleted_secret(self):
        """TEST 19: DescribeSecret - Describe deleted secret"""
        result = self.run_command([
            "aws", "secretsmanager", "describe-secret",
            "--secret-id", self.secret_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("DeletedDate", output)

    def test_20_list_deleted_secrets(self):
        """TEST 20: ListSecrets - List secrets including deleted"""
        result = self.run_command([
            "aws", "secretsmanager", "list-secrets"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        secret_names = [s["Name"] for s in output["SecretList"]]
        self.assertIn(self.secret_name, secret_names)

    def test_21_restore_secret(self):
        """TEST 21: RestoreSecret - Restore deleted secret"""
        result = self.run_command([
            "aws", "secretsmanager", "restore-secret",
            "--secret-id", self.secret_name
        ])
        self.assertEqual(result.returncode, 0)

    def test_22_verify_restored_secret(self):
        """TEST 22: DescribeSecret - Verify secret is restored"""
        result = self.run_command([
            "aws", "secretsmanager", "describe-secret",
            "--secret-id", self.secret_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        # DeletedDate should be null or not present
        deleted_date = output.get("DeletedDate")
        self.assertIsNone(deleted_date)

    def test_23_force_delete_secret(self):
        """TEST 23: DeleteSecret - Force delete secret"""
        result = self.run_command([
            "aws", "secretsmanager", "delete-secret",
            "--secret-id", self.secret_name,
            "--force-delete"
        ])
        self.assertEqual(result.returncode, 0)

    def test_24_verify_secret_permanently_deleted(self):
        """TEST 24: GetSecretValue - Verify secret permanently deleted"""
        time.sleep(1)
        result = self.run_command([
            "aws", "secretsmanager", "describe-secret",
            "--secret-id", self.secret_name
        ], check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_25_create_binary_secret(self):
        """TEST 25: CreateSecret - Create binary secret"""
        binary_b64 = base64.b64encode(self.binary_secret_value.encode()).decode()

        result = self.run_command([
            "aws", "secretsmanager", "create-secret",
            "--name", f"{self.secret_name}-binary",
            "--secret-binary", binary_b64
        ])
        self.assertEqual(result.returncode, 0)

    def test_26_get_binary_secret(self):
        """TEST 26: GetSecretValue - Get binary secret"""
        result = self.run_command([
            "aws", "secretsmanager", "get-secret-value",
            "--secret-id", f"{self.secret_name}-binary"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("SecretBinary", output)

    def test_27_tag_resource(self):
        """TEST 27: TagResource - Tag secret"""
        # Add two tags; test_28 will remove only NewTag, leaving KeepTag for test_29 to verify
        result = self.run_command([
            "aws", "secretsmanager", "tag-resource",
            "--secret-id", f"{self.secret_name}-binary",
            "--tags", "Key=NewTag,Value=NewValue", "Key=KeepTag,Value=KeepValue"
        ])
        self.assertEqual(result.returncode, 0)

    def test_28_untag_resource(self):
        """TEST 28: UntagResource - Untag secret"""
        result = self.run_command([
            "aws", "secretsmanager", "untag-resource",
            "--secret-id", f"{self.secret_name}-binary",
            "--tag-keys", "NewTag"
        ])
        self.assertEqual(result.returncode, 0)

    def test_29_describe_secret_tags(self):
        """TEST 29: DescribeSecret - Check tags"""
        result = self.run_command([
            "aws", "secretsmanager", "describe-secret",
            "--secret-id", f"{self.secret_name}-binary"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Tags", output)
        tag_keys = [t["Key"] for t in output.get("Tags", [])]
        self.assertIn("KeepTag", tag_keys)
        self.assertNotIn("NewTag", tag_keys)

    # def test_30_error_nonexistent_secret(self):
    #     """TEST 30: GetSecretValue - Error for non-existent secret"""
    #     result = self.run_command([
    #         "aws", "secretsmanager", "get-secret-value",
    #         "--secret-id", "non-existent-secret"
    #     ], check=False)
    #     self.assertNotEqual(result.returncode, 0)

    # def test_31_error_duplicate_secret(self):
    #     """TEST 31: CreateSecret - Error for duplicate secret"""
    #     # Create first
    #     self.run_command([
    #         "aws", "secretsmanager", "create-secret",
    #         "--name", "duplicate-test",
    #         "--secret-string", "value1"
    #     ])

    #     # Try to create duplicate
    #     result = self.run_command([
    #         "aws", "secretsmanager", "create-secret",
    #         "--name", "duplicate-test",
    #         "--secret-string", "value2"
    #     ], check=False)
    #     self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
