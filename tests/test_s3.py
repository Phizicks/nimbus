"""
S3 Unit Tests
Tests S3 functionality using AWS CLI commands through subprocess
"""

import unittest
import subprocess
import json
import os
import time
import tempfile


class TestS3(unittest.TestCase):
    """S3 unit tests"""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures - Clean up previous artifacts first"""
        cls._cleanup_previous_artifacts()
        cls.bucket_name = f"test-s3-bucket-{int(time.time())}"
        cls.bucket_name_2 = f"test-s3-bucket-2-{int(time.time())}"
        cls.temp_dir = tempfile.mkdtemp()

        # Create test files
        cls.test_file = os.path.join(cls.temp_dir, "test-file.txt")
        with open(cls.test_file, "w") as f:
            f.write("Hello from S3 unit test!")

        cls.test_file_2 = os.path.join(cls.temp_dir, "test-file-2.txt")
        with open(cls.test_file_2, "w") as f:
            f.write("Second test file content")

        cls.large_file = os.path.join(cls.temp_dir, "large-file.txt")
        with open(cls.large_file, "w") as f:
            f.write("x" * 10000)

        cls.download_file = os.path.join(cls.temp_dir, "downloaded.txt")

    @classmethod
    def _cleanup_previous_artifacts(cls):
        """Clean up any leftover buckets from previous test runs"""
        result = subprocess.run([
            "aws", "s3api", "list-buckets",
            "--endpoint-url", "http://localhost:4566"
        ], capture_output=True, text=True)

        if result.returncode == 0:
            try:
                output = json.loads(result.stdout)
                for bucket in output.get("Buckets", []):
                    bucket_name = bucket.get("Name", "")
                    if bucket_name.startswith("test-s3-bucket"):
                        # Empty the bucket first
                        subprocess.run([
                            "aws", "s3", "rm",
                            f"s3://{bucket_name}",
                            "--recursive",
                            "--endpoint-url", "http://localhost:4566"
                        ], capture_output=True)
                        # Delete the bucket
                        subprocess.run([
                            "aws", "s3api", "delete-bucket",
                            "--bucket", bucket_name,
                            "--endpoint-url", "http://localhost:4566"
                        ], capture_output=True)
            except json.JSONDecodeError:
                pass

    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests"""
        cls._cleanup_previous_artifacts()
        # Clean up temp files
        for f in [cls.test_file, cls.test_file_2, cls.large_file, cls.download_file]:
            try:
                os.remove(f)
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

    def test_01_create_bucket(self):
        """TEST 1: CreateBucket - Create S3 bucket"""
        result = self.run_command([
            "aws", "s3api", "create-bucket",
            "--bucket", self.bucket_name
        ])
        self.assertEqual(result.returncode, 0)

    def test_02_create_second_bucket(self):
        """TEST 2: CreateBucket - Create second S3 bucket"""
        result = self.run_command([
            "aws", "s3api", "create-bucket",
            "--bucket", self.bucket_name_2
        ])
        self.assertEqual(result.returncode, 0)

    def test_03_create_duplicate_bucket_fails(self):
        """TEST 3: CreateBucket - Duplicate bucket should fail"""
        result = self.run_command([
            "aws", "s3api", "create-bucket",
            "--bucket", self.bucket_name
        ], check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_04_list_buckets(self):
        """TEST 4: ListBuckets - List all buckets"""
        result = self.run_command([
            "aws", "s3api", "list-buckets"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        bucket_names = [b["Name"] for b in output["Buckets"]]
        self.assertIn(self.bucket_name, bucket_names)
        self.assertIn(self.bucket_name_2, bucket_names)

    def test_05_head_bucket(self):
        """TEST 5: HeadBucket - Check bucket exists"""
        result = self.run_command([
            "aws", "s3api", "head-bucket",
            "--bucket", self.bucket_name
        ])
        self.assertEqual(result.returncode, 0)

    def test_06_head_nonexistent_bucket_fails(self):
        """TEST 6: HeadBucket - Non-existent bucket should fail"""
        result = self.run_command([
            "aws", "s3api", "head-bucket",
            "--bucket", "non-existent-bucket-xyz-12345"
        ], check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_07_put_object(self):
        """TEST 7: PutObject - Upload file to S3"""
        result = self.run_command([
            "aws", "s3api", "put-object",
            "--bucket", self.bucket_name,
            "--key", "test-file.txt",
            "--body", self.test_file
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("ETag", output)

    def test_08_put_second_object(self):
        """TEST 8: PutObject - Upload second file"""
        result = self.run_command([
            "aws", "s3api", "put-object",
            "--bucket", self.bucket_name,
            "--key", "subdir/test-file-2.txt",
            "--body", self.test_file_2
        ])
        self.assertEqual(result.returncode, 0)

    def test_09_put_large_object(self):
        """TEST 9: PutObject - Upload larger file"""
        result = self.run_command([
            "aws", "s3api", "put-object",
            "--bucket", self.bucket_name,
            "--key", "large-file.txt",
            "--body", self.large_file
        ])
        self.assertEqual(result.returncode, 0)
        time.sleep(3)

    def test_10_head_object(self):
        """TEST 10: HeadObject - Get object metadata"""
        result = self.run_command([
            "aws", "s3api", "head-object",
            "--bucket", self.bucket_name,
            "--key", "large-file.txt"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("ContentLength", output)
        self.assertGreater(output["ContentLength"], 0)

    def test_11_get_object(self):
        """TEST 11: GetObject - Download object from S3"""
        result = self.run_command([
            "aws", "s3api", "get-object",
            "--bucket", self.bucket_name,
            "--key", "test-file.txt",
            self.download_file
        ])
        self.assertEqual(result.returncode, 0)

        # Verify content
        with open(self.download_file, "r") as f:
            content = f.read()
        self.assertEqual(content, "Hello from S3 unit test!")

    def test_12_list_objects(self):
        """TEST 12: ListObjectsV2 - List objects in bucket"""
        result = self.run_command([
            "aws", "s3api", "list-objects-v2",
            "--bucket", self.bucket_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Contents", output)
        keys = [obj["Key"] for obj in output["Contents"]]
        self.assertIn("test-file.txt", keys)

    def test_13_list_objects_with_prefix(self):
        """TEST 13: ListObjectsV2 - List objects with prefix"""
        result = self.run_command([
            "aws", "s3api", "list-objects-v2",
            "--bucket", self.bucket_name,
            "--prefix", "subdir/"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Contents", output)
        keys = [obj["Key"] for obj in output["Contents"]]
        self.assertIn("subdir/test-file-2.txt", keys)

    def test_14_copy_object(self):
        """TEST 14: CopyObject - Copy object within bucket"""
        result = self.run_command([
            "aws", "s3api", "copy-object",
            "--bucket", self.bucket_name,
            "--copy-source", f"{self.bucket_name}/test-file.txt",
            "--key", "test-file-copy.txt"
        ])
        self.assertEqual(result.returncode, 0)

    def test_15_verify_copy(self):
        """TEST 15: Verify copied object exists"""
        result = self.run_command([
            "aws", "s3api", "head-object",
            "--bucket", self.bucket_name,
            "--key", "test-file-copy.txt"
        ])
        self.assertEqual(result.returncode, 0)

    def test_16_delete_object(self):
        """TEST 16: DeleteObject - Delete single object"""
        result = self.run_command([
            "aws", "s3api", "delete-object",
            "--bucket", self.bucket_name,
            "--key", "test-file-copy.txt"
        ])
        self.assertEqual(result.returncode, 0)

    def test_17_verify_object_deleted(self):
        """TEST 17: Verify object is deleted"""
        result = self.run_command([
            "aws", "s3api", "head-object",
            "--bucket", self.bucket_name,
            "--key", "test-file-copy.txt"
        ], check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_18_delete_objects_batch(self):
        """TEST 18: DeleteObjects - Delete multiple objects"""
        result = self.run_command([
            "aws", "s3api", "delete-objects",
            "--bucket", self.bucket_name,
            "--delete", json.dumps({
                "Objects": [
                    {"Key": "test-file.txt"},
                    {"Key": "subdir/test-file-2.txt"},
                    {"Key": "large-file.txt"}
                ]
            })
        ])
        self.assertEqual(result.returncode, 0)

    def test_19_verify_bucket_empty(self):
        """TEST 19: Verify bucket is empty after batch delete"""
        result = self.run_command([
            "aws", "s3api", "list-objects-v2",
            "--bucket", self.bucket_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output.get("KeyCount", 0), 0)

    def test_20_delete_bucket(self):
        """TEST 20: DeleteBucket - Delete empty bucket"""
        result = self.run_command([
            "aws", "s3api", "delete-bucket",
            "--bucket", self.bucket_name
        ])
        self.assertEqual(result.returncode, 0)

    def test_21_delete_second_bucket(self):
        """TEST 21: DeleteBucket - Delete second bucket"""
        result = self.run_command([
            "aws", "s3api", "delete-bucket",
            "--bucket", self.bucket_name_2
        ])
        self.assertEqual(result.returncode, 0)
        # Allow time for log indexing
        time.sleep(2)

    def test_22_verify_bucket_deleted(self):
        """TEST 22: Verify bucket is deleted"""
        result = self.run_command([
            "aws", "s3api", "head-bucket",
            "--bucket", self.bucket_name
        ], check=False)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
