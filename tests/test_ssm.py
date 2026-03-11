"""
SSM Parameter Store Unit Tests
Tests SSM Parameter Store functionality using AWS CLI commands through subprocess
Preserves exact command execution from original bash tests
"""

import unittest
import subprocess
import json
import os


class TestSSM(unittest.TestCase):
    """SSM Parameter Store unit tests"""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures - Clean up previous artifacts first"""
        cls._cleanup_previous_artifacts()

    @classmethod
    def _cleanup_previous_artifacts(cls):
        """Clean up any leftover parameters from previous test runs"""
        for param_name in ["/my/parameter", "/secure/parameter", "/test/parameter"]:
            subprocess.run([
                "aws", "ssm", "delete-parameter",
                "--name", param_name,
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

    def test_01_put_parameter(self):
        """TEST 1: PutParameter - Create a new parameter"""
        result = self.run_command([
            "aws", "ssm", "put-parameter",
            "--name", "/my/parameter",
            "--value", "value-1",
            "--overwrite"
        ])
        self.assertEqual(result.returncode, 0)

    def test_02_get_parameter(self):
        """TEST 2: GetParameter - Get a specific parameter"""
        result = self.run_command([
            "aws", "ssm", "get-parameter",
            "--name", "/my/parameter",
            "--with-decryption"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Parameter", output)
        self.assertEqual(output["Parameter"]["Name"], "/my/parameter")

    def test_03_get_parameters(self):
        """TEST 3: GetParameters - Get parameters by names"""
        result = self.run_command([
            "aws", "ssm", "get-parameters",
            "--names", "/my/parameter",
            "--with-decryption"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Parameters", output)

    def test_04_update_parameter(self):
        """TEST 4: PutParameter - Update parameter value with overwrite"""
        result = self.run_command([
            "aws", "ssm", "put-parameter",
            "--name", "/my/parameter",
            "--value", "value-2",
            "--overwrite"
        ])
        self.assertEqual(result.returncode, 0)

    def test_05_version_increment(self):
        """TEST 5: GetParameter - Verify version incremented after update"""
        result = self.run_command([
            "aws", "ssm", "get-parameter",
            "--name", "/my/parameter"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        version = output["Parameter"]["Version"]
        self.assertEqual(version, 2, f"Parameter version should be 2, got {version}")

    def test_06_list_tags_for_resource(self):
        """TEST 6: ListTagsForResource - List tags for a parameter"""
        result = self.run_command([
            "aws", "ssm", "list-tags-for-resource",
            "--resource-type", "Parameter",
            "--resource-id", "/my/parameter"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("TagList", output)

    def test_07_put_secure_string_parameter(self):
        """TEST 7: PutParameter - Store secure string parameter with tags"""
        # Ensure clean state
        self.run_command([
            "aws", "ssm", "delete-parameter",
            "--name", "/secure/parameter"
        ], check=False)

        result = self.run_command([
            "aws", "ssm", "put-parameter",
            "--name", "/secure/parameter",
            "--value", "securestring",
            "--type", "SecureString",
            "--tags", "Key=Environment,Value=Test", "Key=Owner,Value=DevOps"
        ])
        self.assertEqual(result.returncode, 0)

    def test_08_get_secure_string_without_decryption(self):
        """TEST 8: GetParameter - Secure string without decryption returns encrypted value"""
        result = self.run_command([
            "aws", "ssm", "get-parameter",
            "--name", "/secure/parameter"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        value = output["Parameter"]["Value"]
        # Without --with-decryption, the value should be encrypted (not the original plaintext)
        self.assertNotEqual(value, "securestring",
                            "Secure string should be encrypted when retrieved without --with-decryption")

    def test_09_describe_parameters(self):
        """TEST 9: DescribeParameters - Describe parameters with filter"""
        result = self.run_command([
            "aws", "ssm", "describe-parameters",
            "--parameter-filters", "Key=Type,Values=SecureString"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Parameters", output)

    def test_10_describe_parameters_json(self):
        """TEST 10: DescribeParameters - List all parameters in JSON"""
        result = self.run_command([
            "aws", "ssm", "describe-parameters",
            "--output", "json"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Parameters", output)

    def test_11_describe_parameters_text(self):
        """TEST 11: DescribeParameters - List all parameters in TEXT"""
        result = self.run_command([
            "aws", "ssm", "describe-parameters",
            "--output", "text"
        ])
        self.assertEqual(result.returncode, 0)

    def test_12_put_without_overwrite_fails(self):
        """TEST 12: PutParameter - Put without overwrite on existing parameter should fail"""
        result = self.run_command([
            "aws", "ssm", "put-parameter",
            "--name", "/my/parameter",
            "--value", "new-value"
        ], check=False)
        # Should fail because parameter exists and --overwrite not specified
        self.assertNotEqual(result.returncode, 0)

    def test_13_put_type_change_without_delete_fails(self):
        """TEST 13: PutParameter - Changing type with overwrite should fail"""
        result = self.run_command([
            "aws", "ssm", "put-parameter",
            "--name", "/my/parameter",
            "--value", "new-secure-value",
            "--overwrite",
            "--type", "SecureString"
        ], check=False)
        # Changing type without deleting first should fail
        self.assertNotEqual(result.returncode, 0)

    def test_14_delete_parameter(self):
        """TEST 14: DeleteParameter - Delete a parameter"""
        result = self.run_command([
            "aws", "ssm", "delete-parameter",
            "--name", "/my/parameter"
        ])
        self.assertEqual(result.returncode, 0)

    def test_15_get_deleted_parameter_fails(self):
        """TEST 15: GetParameter - Get deleted parameter should fail"""
        result = self.run_command([
            "aws", "ssm", "get-parameter",
            "--name", "/my/parameter"
        ], check=False)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
