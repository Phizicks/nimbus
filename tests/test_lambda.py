"""
Lambda Unit Tests
Tests Lambda functionality using AWS CLI commands through subprocess
Preserves exact command execution from original bash tests
"""

import unittest
import subprocess
import json
import os
import zipfile
import tempfile
from pathlib import Path


class TestLambda(unittest.TestCase):
    """Lambda unit tests"""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures - Clean up previous artifacts first"""
        # Define function name FIRST before cleanup
        cls.function_name = "python3-function"

        # PRE-CLEANUP: Remove any leftover functions from previous test runs
        cls._cleanup_previous_artifacts()

        cls.temp_dir = tempfile.mkdtemp()

        # Create Python test function
        lambda_code = """
def handler(event, context):
    name = event.get('name', 'World')
    return {
        'statusCode': 200,
        'body': f'Hello {name}!'
    }
"""
        cls.code_file = os.path.join(cls.temp_dir, "lambda_function.py")
        with open(cls.code_file, "w") as f:
            f.write(lambda_code)

    @classmethod
    def _cleanup_previous_artifacts(cls):
        """Clean up any leftover Lambda functions from previous test runs"""
        # subprocess.run([
        #     "aws", "lambda", "delete-function",
        #     "--function-name", cls.function_name,
        #     "--endpoint-url", "http://localhost:4566"
        # ], capture_output=True)
        pass

    @classmethod
    def tearDownClass(cls):
        """Clean up test fixtures"""
        # Use the same cleanup method as pre-test
        cls._cleanup_previous_artifacts()

        # Clean up temp files
        for file in os.listdir(cls.temp_dir):
            try:
                os.remove(os.path.join(cls.temp_dir, file))
            except:
                pass
        try:
            os.rmdir(cls.temp_dir)
        except:
            pass

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

    def test_01_delete_existing_function(self):
        """TEST 0: Delete existing function if it exists"""
        self.run_command([
            "aws", "lambda", "delete-function",
            "--function-name", self.function_name
        ], check=False)

    def test_02_create_function_from_zip(self):
        """TEST 1: CreateFunction - Create function with ZIP"""
        # Create ZIP file
        zip_file = os.path.join(self.temp_dir, "function.zip")
        with zipfile.ZipFile(zip_file, "w") as zf:
            zf.write(self.code_file, arcname="lambda_function.py")

        result = self.run_command([
            "aws", "lambda", "create-function",
            "--function-name", self.function_name,
            "--runtime", "python3.11",
            "--handler", "lambda_function.handler",
            "--zip-file", f"fileb://{zip_file}",
            "--role", "arn:aws:iam::456645664566:role/lambda-role"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["FunctionName"], self.function_name)

    def test_03_get_function(self):
        """TEST 2: GetFunction - Get function configuration"""
        result = self.run_command([
            "aws", "lambda", "get-function",
            "--function-name", self.function_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Configuration", output)
        self.assertEqual(output["Configuration"]["FunctionName"], self.function_name)

    def test_04_get_function_configuration(self):
        """TEST 3: GetFunctionConfiguration - Get only configuration"""
        result = self.run_command([
            "aws", "lambda", "get-function-configuration",
            "--function-name", self.function_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["FunctionName"], self.function_name)
        self.assertEqual(output["Runtime"], "python3.11")

    def test_05_invoke_function(self):
        """TEST 4: InvokeFunction - Invoke function with payload"""
        result = self.run_command([
            "aws", "lambda", "invoke",
            "--function-name", self.function_name,
            "--cli-binary-format", "raw-in-base64-out",
            "--payload", '{"name":"TESTOK"}',
            "/tmp/response.json"
        ])
        self.assertEqual(result.returncode, 0)

        # Check response file
        self.assertTrue(os.path.exists("/tmp/response.json"))
        with open("/tmp/response.json") as f:
            response = json.load(f)
        self.assertEqual(response["statusCode"], 200)

    def test_06_update_function_code(self):
        """TEST 5: UpdateFunctionCode - Update function code"""
        # Modify code
        new_code = """
def handler(event, context):
    return {
        'statusCode': 200,
        'body': 'Updated function'
    }
"""
        code_file = os.path.join(self.temp_dir, "lambda_function_v2.py")
        with open(code_file, "w") as f:
            f.write(new_code)

        # Create ZIP
        zip_file = os.path.join(self.temp_dir, "function_v2.zip")
        with zipfile.ZipFile(zip_file, "w") as zf:
            zf.write(code_file, arcname="lambda_function.py")

        result = self.run_command([
            "aws", "lambda", "update-function-code",
            "--function-name", self.function_name,
            "--zip-file", f"fileb://{zip_file}"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["FunctionName"], self.function_name)

    def test_07_update_function_configuration(self):
        """TEST 6: UpdateFunctionConfiguration - Update configuration"""
        result = self.run_command([
            "aws", "lambda", "update-function-configuration",
            "--function-name", self.function_name,
            "--timeout", "60",
            "--memory-size", "256"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["Timeout"], 60)
        self.assertEqual(output["MemorySize"], 256)

    def test_08_list_functions(self):
        """TEST 7: ListFunctions - List all functions"""
        result = self.run_command([
            "aws", "lambda", "list-functions"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Functions", output)
        function_names = [f["FunctionName"] for f in output["Functions"]]
        self.assertIn(self.function_name, function_names)

    def test_09_get_function_concurrency(self):
        """TEST 8: GetFunctionConcurrency - Get reserved concurrency"""
        result = self.run_command([
            "aws", "lambda", "get-function-concurrency",
            "--function-name", self.function_name
        ], check=False)
        # May not be set, so we don't check return code
        if result.returncode == 0:
            output = json.loads(result.stdout)
            self.assertIn("ReservedConcurrentExecutions", output)

    def test_10_put_function_concurrency(self):
        """TEST 9: PutFunctionConcurrency - Set reserved concurrency"""
        result = self.run_command([
            "aws", "lambda", "put-function-concurrency",
            "--function-name", self.function_name,
            "--reserved-concurrent-executions", "5"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["ReservedConcurrentExecutions"], 5)

    def test_11_delete_function_concurrency(self):
        """TEST 10: DeleteFunctionConcurrency - Delete reserved concurrency"""
        result = self.run_command([
            "aws", "lambda", "delete-function-concurrency",
            "--function-name", self.function_name
        ])
        self.assertEqual(result.returncode, 0)

    def test_12_delete_function(self):
        """TEST 11: DeleteFunction - Delete function"""
        result = self.run_command([
            "aws", "lambda", "delete-function",
            "--function-name", self.function_name
        ])
        self.assertEqual(result.returncode, 0)

    def test_13_verify_function_deleted(self):
        """TEST 12: Verify function is deleted"""
        result = self.run_command([
            "aws", "lambda", "get-function",
            "--function-name", self.function_name
        ], check=False)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
