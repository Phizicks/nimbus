"""
ECR (Elastic Container Registry) Unit Tests
Tests ECR functionality using AWS CLI commands through subprocess
Preserves exact command execution from original bash tests
"""

import unittest
import subprocess
import json
import os
import sys
import time
import tempfile
from datetime import datetime
from pathlib import Path


class TestECR(unittest.TestCase):
    """ECR unit tests"""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures - Clean up previous artifacts first"""
        # PRE-CLEANUP: Remove any leftover repositories from previous test runs
        cls._cleanup_previous_artifacts()
        
        cls.repository_name = f"test-ecr-repo-{int(time.time())}"
        cls.repository_name_2 = f"test-ecr-repo-2-{int(time.time())}"
        cls.image_tag = "latest"
        cls.image_tag_2 = "v1.0.0"
        cls.image_tag_3 = "v2.0.0"
        cls.dockerfile_path = "."
        cls.temp_dir = tempfile.mkdtemp()
        
        # Create test Dockerfile
        dockerfile_content = """FROM public.ecr.aws/lambda/python:3.11
CMD ["lambda_function.handler"]
"""
        dockerfile_path = os.path.join(cls.dockerfile_path, "Dockerfile")
        with open(dockerfile_path, "w") as f:
            f.write(dockerfile_content)

    @classmethod
    def _cleanup_previous_artifacts(cls):
        """Clean up any leftover repositories from previous test runs"""
        # List all repositories and delete those matching our test pattern
        result = subprocess.run([
            "aws", "ecr", "describe-repositories",
            "--endpoint-url", "http://localhost:4566"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            try:
                output = json.loads(result.stdout)
                for repo in output.get("repositories", []):
                    repo_name = repo.get("repositoryName", "")
                    if repo_name.startswith("test-ecr-repo"):
                        subprocess.run([
                            "aws", "ecr", "delete-repository",
                            "--repository-name", repo_name,
                            "--force",
                            "--endpoint-url", "http://localhost:4566"
                        ], capture_output=True)
            except json.JSONDecodeError:
                pass

    @classmethod
    def tearDownClass(cls):
        """Clean up test fixtures"""
        # Use the same cleanup method as pre-test
        cls._cleanup_previous_artifacts()
        
        # Clean up Docker images
        subprocess.run(
            ["docker", "rmi", f"{cls.repository_name}:{cls.image_tag}"],
            capture_output=True
        )
        subprocess.run(
            ["docker", "rmi", f"{cls.repository_name}:{cls.image_tag_2}"],
            capture_output=True
        )
        subprocess.run(
            ["docker", "rmi", f"{cls.repository_name}:{cls.image_tag_3}"],
            capture_output=True
        )
        
        # Remove temp files
        for file in ["response.json", "test-image.tar", "Dockerfile"]:
            try:
                os.remove(file)
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

    def test_01_create_repository(self):
        """TEST 1: CreateRepository - Create first repository"""
        result = self.run_command([
            "aws", "ecr", "create-repository",
            "--repository-name", self.repository_name
        ])
        self.assertEqual(result.returncode, 0, f"Failed to create repository: {result.stderr}")
        output = json.loads(result.stdout)
        self.assertIn("repository", output)
        self.assertEqual(output["repository"]["repositoryName"], self.repository_name)

    def test_02_create_second_repository(self):
        """TEST 2: CreateRepository - Create second repository"""
        result = self.run_command([
            "aws", "ecr", "create-repository",
            "--repository-name", self.repository_name_2
        ])
        self.assertEqual(result.returncode, 0, f"Failed to create second repository: {result.stderr}")

    def test_03_create_duplicate_fails(self):
        """TEST 3: CreateRepository - Duplicate repository should fail"""
        result = self.run_command([
            "aws", "ecr", "create-repository",
            "--repository-name", self.repository_name
        ], check=False)
        self.assertNotEqual(result.returncode, 0, "Should fail when creating duplicate repository")

    def test_04_describe_repositories_list_all(self):
        """TEST 4: DescribeRepositories - List all repositories"""
        result = self.run_command([
            "aws", "ecr", "describe-repositories"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        repo_names = [repo["repositoryName"] for repo in output["repositories"]]
        self.assertIn(self.repository_name, repo_names)

    def test_05_describe_repositories_specific(self):
        """TEST 5: DescribeRepositories - Describe specific repository"""
        result = self.run_command([
            "aws", "ecr", "describe-repositories",
            "--repository-names", self.repository_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("repositoryUri", output["repositories"][0])

    def test_06_describe_nonexistent_fails(self):
        """TEST 6: DescribeRepositories - Non-existent repository should fail"""
        result = self.run_command([
            "aws", "ecr", "describe-repositories",
            "--repository-names", "non-existent-repo"
        ], check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_07_docker_build(self):
        """TEST 7: Docker build - Build test image"""
        result = self.run_command([
            "docker", "build",
            "-t", f"{self.repository_name}:{self.image_tag}",
            self.dockerfile_path
        ])
        self.assertEqual(result.returncode, 0, f"Failed to build Docker image: {result.stderr}")

    def test_08_get_authorization_token(self):
        """TEST 8: GetAuthorizationToken - ECR login"""
        result = self.run_command([
            "aws", "ecr", "get-authorization-token"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("authorizationData", output)

    def test_09_docker_tag_for_ecr(self):
        """TEST 9: Docker tag - Tag image for ECR"""
        # Get ECR URI
        result = self.run_command([
            "aws", "ecr", "describe-repositories",
            "--repository-names", self.repository_name
        ])
        output = json.loads(result.stdout)
        ecr_uri = output["repositories"][0]["repositoryUri"]
        
        # Tag image
        result = self.run_command([
            "docker", "tag",
            f"{self.repository_name}:{self.image_tag}",
            f"{ecr_uri}:{self.image_tag}"
        ])
        self.assertEqual(result.returncode, 0)

    def test_10_docker_push_image(self):
        """TEST 10: PutImage - Push image to ECR"""
        # Get ECR URI
        result = self.run_command([
            "aws", "ecr", "describe-repositories",
            "--repository-names", self.repository_name
        ])
        output = json.loads(result.stdout)
        ecr_uri = output["repositories"][0]["repositoryUri"]
        
        # Push image (this also tags it internally)
        result = self.run_command([
            "docker", "push", f"{ecr_uri}:{self.image_tag}"
        ])
        self.assertEqual(result.returncode, 0, f"Failed to push image: {result.stderr}")

    def test_11_push_second_tag(self):
        """TEST 11: PutImage - Push second tag"""
        result = self.run_command([
            "aws", "ecr", "describe-repositories",
            "--repository-names", self.repository_name
        ])
        output = json.loads(result.stdout)
        ecr_uri = output["repositories"][0]["repositoryUri"]
        
        # Tag and push second version
        self.run_command([
            "docker", "tag",
            f"{self.repository_name}:{self.image_tag}",
            f"{ecr_uri}:{self.image_tag_2}"
        ])
        result = self.run_command([
            "docker", "push", f"{ecr_uri}:{self.image_tag_2}"
        ])
        self.assertEqual(result.returncode, 0)

    def test_12_list_images(self):
        """TEST 12: ListImages - List images in repository"""
        result = self.run_command([
            "aws", "ecr", "list-images",
            "--repository-name", self.repository_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        tags = [img.get("imageTag") for img in output["imageIds"]]
        self.assertIn(self.image_tag, tags)

    def test_13_list_images_verify_both_tags(self):
        """TEST 13: ListImages - Verify both tags exist"""
        result = self.run_command([
            "aws", "ecr", "list-images",
            "--repository-name", self.repository_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        tags = [img.get("imageTag") for img in output["imageIds"]]
        self.assertIn(self.image_tag_2, tags)

    def test_14_describe_images(self):
        """TEST 14: DescribeImages - Describe all images"""
        result = self.run_command([
            "aws", "ecr", "describe-images",
            "--repository-name", self.repository_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertGreater(len(output["imageDetails"]), 0)
        self.assertIn("imageTags", output["imageDetails"][0])

    def test_15_describe_specific_image(self):
        """TEST 15: DescribeImages - Describe specific image by tag"""
        result = self.run_command([
            "aws", "ecr", "describe-images",
            "--repository-name", self.repository_name,
            "--image-ids", f"imageTag={self.image_tag}"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("imageDigest", output["imageDetails"][0])

    def test_16_batch_get_image(self):
        """TEST 16: BatchGetImage - Get image manifest"""
        result = self.run_command([
            "aws", "ecr", "batch-get-image",
            "--repository-name", self.repository_name,
            "--image-ids", f"imageTag={self.image_tag}"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("images", output)
        self.assertIn("imageManifest", output["images"][0])

    def test_17_batch_delete_single_image(self):
        """TEST 17: BatchDeleteImage - Delete single image by tag"""
        result = self.run_command([
            "aws", "ecr", "batch-delete-image",
            "--repository-name", self.repository_name,
            "--image-ids", f"imageTag={self.image_tag_2}"
        ])
        self.assertEqual(result.returncode, 0)

    def test_18_verify_image_deleted(self):
        """TEST 18: Verify image was deleted from registry"""
        result = self.run_command([
            "aws", "ecr", "list-images",
            "--repository-name", self.repository_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        tags = [img.get("imageTag") for img in output["imageIds"]]
        self.assertNotIn(self.image_tag_2, tags)

    def test_19_push_third_tag(self):
        """TEST 19: Push v2.0.0 tag for multi-delete test"""
        result = self.run_command([
            "aws", "ecr", "describe-repositories",
            "--repository-names", self.repository_name
        ])
        output = json.loads(result.stdout)
        ecr_uri = output["repositories"][0]["repositoryUri"]
        
        self.run_command([
            "docker", "tag",
            f"{self.repository_name}:{self.image_tag}",
            f"{ecr_uri}:{self.image_tag_3}"
        ])
        result = self.run_command([
            "docker", "push", f"{ecr_uri}:{self.image_tag_3}"
        ])
        self.assertEqual(result.returncode, 0)

    def test_20_batch_delete_multiple_images(self):
        """TEST 20: BatchDeleteImage - Delete multiple images"""
        result = self.run_command([
            "aws", "ecr", "batch-delete-image",
            "--repository-name", self.repository_name,
            "--image-ids", f"imageTag={self.image_tag}", f"imageTag={self.image_tag_3}"
        ])
        self.assertEqual(result.returncode, 0)

    def test_21_verify_images_deleted(self):
        """TEST 21: Verify both images deleted"""
        result = self.run_command([
            "aws", "ecr", "list-images",
            "--repository-name", self.repository_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        tags = [img.get("imageTag") for img in output["imageIds"]]
        self.assertNotIn(self.image_tag, tags)
        self.assertNotIn(self.image_tag_3, tags)

    def test_22_delete_repo_without_force_fails(self):
        """TEST 22: DeleteRepository - Delete with images should fail without force"""
        # Push an image first for a fresh repo
        result = self.run_command([
            "aws", "ecr", "describe-repositories",
            "--repository-names", self.repository_name
        ])
        output = json.loads(result.stdout)
        ecr_uri = output["repositories"][0]["repositoryUri"]
        
        # Re-push the test image
        self.run_command([
            "docker", "push", f"{ecr_uri}:{self.image_tag}"
        ])
        
        # Try to delete without force (should fail)
        result = self.run_command([
            "aws", "ecr", "delete-repository",
            "--repository-name", self.repository_name
        ], check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_23_delete_repository_with_force(self):
        """TEST 23: DeleteRepository - Delete with force flag"""
        result = self.run_command([
            "aws", "ecr", "delete-repository",
            "--repository-name", self.repository_name,
            "--force"
        ])
        self.assertEqual(result.returncode, 0)

    def test_24_verify_repository_deleted(self):
        """TEST 24: Verify repository is deleted"""
        result = self.run_command([
            "aws", "ecr", "describe-repositories",
            "--repository-names", self.repository_name
        ], check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_25_recreate_repository_no_zombie_images(self):
        """TEST 25: CRITICAL - Verify no zombie images after repository recreation"""
        # Recreate repository
        result = self.run_command([
            "aws", "ecr", "create-repository",
            "--repository-name", self.repository_name
        ])
        self.assertEqual(result.returncode, 0)
        
        # Check that no images exist
        result = self.run_command([
            "aws", "ecr", "describe-images",
            "--repository-name", self.repository_name
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(len(output["imageDetails"]), 0, "Recreated repository should have no images")

    def test_26_delete_empty_repository(self):
        """TEST 26: DeleteRepository - Delete empty repository"""
        result = self.run_command([
            "aws", "ecr", "delete-repository",
            "--repository-name", self.repository_name
        ])
        self.assertEqual(result.returncode, 0)

    def test_27_delete_second_test_repository(self):
        """TEST 27: DeleteRepository - Delete second test repository"""
        result = self.run_command([
            "aws", "ecr", "delete-repository",
            "--repository-name", self.repository_name_2
        ])
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
