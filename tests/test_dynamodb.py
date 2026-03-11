"""
DynamoDB Unit Tests
Tests DynamoDB functionality using AWS CLI commands through subprocess
Preserves exact command execution from original bash tests
"""

import unittest
import subprocess
import json
import os
import time


class TestDynamoDB(unittest.TestCase):
    """DynamoDB unit tests"""

    TABLE_NAME = "test-dynamodb-table"

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures - Clean up previous artifacts first"""
        cls._cleanup_previous_artifacts()

    @classmethod
    def _cleanup_previous_artifacts(cls):
        """Clean up any leftover tables from previous test runs"""
        for table in [cls.TABLE_NAME, f"{cls.TABLE_NAME}-copy"]:
            subprocess.run([
                "aws", "dynamodb", "delete-table",
                "--table-name", table,
                "--endpoint-url", "http://localhost:4566"
            ], capture_output=True)
        # Allow time for deletion to complete
        time.sleep(1)

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

    def test_01_create_table(self):
        """TEST 1: CreateTable - Create DynamoDB table with hash and range key"""
        result = self.run_command([
            "aws", "dynamodb", "create-table",
            "--table-name", self.TABLE_NAME,
            "--attribute-definitions",
            "AttributeName=id,AttributeType=S",
            "AttributeName=timestamp,AttributeType=N",
            "--key-schema",
            "AttributeName=id,KeyType=HASH",
            "AttributeName=timestamp,KeyType=RANGE",
            "--billing-mode", "PAY_PER_REQUEST",
            "--tags", "Key=Environment,Value=test", "Key=Purpose,Value=unittest"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("TableDescription", output)
        self.assertEqual(output["TableDescription"]["TableName"], self.TABLE_NAME)

    def test_02_list_tables(self):
        """TEST 2: ListTables - List DynamoDB tables"""
        result = self.run_command([
            "aws", "dynamodb", "list-tables"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("TableNames", output)
        self.assertIn(self.TABLE_NAME, output["TableNames"])

    def test_03_describe_table(self):
        """TEST 3: DescribeTable - Describe DynamoDB table"""
        result = self.run_command([
            "aws", "dynamodb", "describe-table",
            "--table-name", self.TABLE_NAME
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Table", output)
        self.assertEqual(output["Table"]["TableName"], self.TABLE_NAME)

    def test_04_put_item(self):
        """TEST 4: PutItem - Put item into table"""
        result = self.run_command([
            "aws", "dynamodb", "put-item",
            "--table-name", self.TABLE_NAME,
            "--item", json.dumps({
                "id": {"S": "test-id-001"},
                "timestamp": {"N": "1234567890"},
                "name": {"S": "Test Item"},
                "value": {"N": "42"},
                "tags": {"SS": ["test", "example", "demo"]},
                "metadata": {"M": {
                    "created_by": {"S": "unittest"},
                    "version": {"N": "1"}
                }}
            })
        ])
        self.assertEqual(result.returncode, 0)

    def test_05_get_item(self):
        """TEST 5: GetItem - Get item from table"""
        result = self.run_command([
            "aws", "dynamodb", "get-item",
            "--table-name", self.TABLE_NAME,
            "--key", json.dumps({
                "id": {"S": "test-id-001"},
                "timestamp": {"N": "1234567890"}
            })
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Item", output)
        self.assertEqual(output["Item"]["name"]["S"], "Test Item")

    def test_06_update_item(self):
        """TEST 6: UpdateItem - Update item with expression"""
        result = self.run_command([
            "aws", "dynamodb", "update-item",
            "--table-name", self.TABLE_NAME,
            "--key", json.dumps({
                "id": {"S": "test-id-001"},
                "timestamp": {"N": "1234567890"}
            }),
            "--update-expression", "SET #v = :val, #n = :name",
            "--expression-attribute-names", json.dumps({
                "#v": "value",
                "#n": "name"
            }),
            "--expression-attribute-values", json.dumps({
                ":val": {"N": "100"},
                ":name": {"S": "Updated Item"}
            }),
            "--return-values", "ALL_NEW"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Attributes", output)
        self.assertEqual(output["Attributes"]["value"]["N"], "100")
        self.assertEqual(output["Attributes"]["name"]["S"], "Updated Item")

    def test_07_batch_write_items(self):
        """TEST 7: BatchWriteItem - Batch write items"""
        result = self.run_command([
            "aws", "dynamodb", "batch-write-item",
            "--request-items", json.dumps({
                self.TABLE_NAME: [
                    {
                        "PutRequest": {
                            "Item": {
                                "id": {"S": "batch-001"},
                                "timestamp": {"N": "1000000001"},
                                "name": {"S": "Batch Item 1"}
                            }
                        }
                    },
                    {
                        "PutRequest": {
                            "Item": {
                                "id": {"S": "batch-002"},
                                "timestamp": {"N": "1000000002"},
                                "name": {"S": "Batch Item 2"}
                            }
                        }
                    },
                    {
                        "PutRequest": {
                            "Item": {
                                "id": {"S": "batch-003"},
                                "timestamp": {"N": "1000000003"},
                                "name": {"S": "Batch Item 3"}
                            }
                        }
                    }
                ]
            })
        ])
        self.assertEqual(result.returncode, 0)

    def test_08_batch_get_items(self):
        """TEST 8: BatchGetItem - Batch get items"""
        result = self.run_command([
            "aws", "dynamodb", "batch-get-item",
            "--request-items", json.dumps({
                self.TABLE_NAME: {
                    "Keys": [
                        {
                            "id": {"S": "batch-001"},
                            "timestamp": {"N": "1000000001"}
                        },
                        {
                            "id": {"S": "batch-002"},
                            "timestamp": {"N": "1000000002"}
                        }
                    ]
                }
            })
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Responses", output)
        self.assertEqual(len(output["Responses"][self.TABLE_NAME]), 2)

    def test_09_query(self):
        """TEST 9: Query - Query items by partition key"""
        result = self.run_command([
            "aws", "dynamodb", "query",
            "--table-name", self.TABLE_NAME,
            "--key-condition-expression", "id = :id",
            "--expression-attribute-values", json.dumps({
                ":id": {"S": "test-id-001"}
            })
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["Count"], 1)

    def test_10_scan(self):
        """TEST 10: Scan - Scan table with filter"""
        result = self.run_command([
            "aws", "dynamodb", "scan",
            "--table-name", self.TABLE_NAME,
            "--filter-expression", "begins_with(id, :prefix)",
            "--expression-attribute-values", json.dumps({
                ":prefix": {"S": "batch"}
            })
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertGreaterEqual(output["Count"], 1)

    def test_11_conditional_update_positive(self):
        """TEST 11: UpdateItem - Conditional update (positive case)"""
        result = self.run_command([
            "aws", "dynamodb", "update-item",
            "--table-name", self.TABLE_NAME,
            "--key", json.dumps({
                "id": {"S": "test-id-001"},
                "timestamp": {"N": "1234567890"}
            }),
            "--update-expression", "SET #v = :newval",
            "--condition-expression", "#v = :oldval",
            "--expression-attribute-names", json.dumps({
                "#v": "value"
            }),
            "--expression-attribute-values", json.dumps({
                ":newval": {"N": "200"},
                ":oldval": {"N": "100"}
            })
        ])
        self.assertEqual(result.returncode, 0)

    def test_12_conditional_update_negative(self):
        """TEST 12: UpdateItem - Conditional update (negative case - should fail)"""
        result = self.run_command([
            "aws", "dynamodb", "update-item",
            "--table-name", self.TABLE_NAME,
            "--key", json.dumps({
                "id": {"S": "test-id-001"},
                "timestamp": {"N": "1234567890"}
            }),
            "--update-expression", "SET #v = :newval",
            "--condition-expression", "#v = :oldval",
            "--expression-attribute-names", json.dumps({
                "#v": "value"
            }),
            "--expression-attribute-values", json.dumps({
                ":newval": {"N": "300"},
                ":oldval": {"N": "999"}
            })
        ], check=False)
        self.assertNotEqual(result.returncode, 0, "Conditional update should have failed")

    def test_13_delete_item(self):
        """TEST 13: DeleteItem - Delete item with return values"""
        result = self.run_command([
            "aws", "dynamodb", "delete-item",
            "--table-name", self.TABLE_NAME,
            "--key", json.dumps({
                "id": {"S": "batch-003"},
                "timestamp": {"N": "1000000003"}
            }),
            "--return-values", "ALL_OLD"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Attributes", output)
        self.assertEqual(output["Attributes"]["name"]["S"], "Batch Item 3")

    def test_14_batch_delete_items(self):
        """TEST 14: BatchWriteItem - Batch delete items"""
        result = self.run_command([
            "aws", "dynamodb", "batch-write-item",
            "--request-items", json.dumps({
                self.TABLE_NAME: [
                    {
                        "DeleteRequest": {
                            "Key": {
                                "id": {"S": "batch-001"},
                                "timestamp": {"N": "1000000001"}
                            }
                        }
                    },
                    {
                        "DeleteRequest": {
                            "Key": {
                                "id": {"S": "batch-002"},
                                "timestamp": {"N": "1000000002"}
                            }
                        }
                    }
                ]
            })
        ])
        self.assertEqual(result.returncode, 0)

    def test_15_list_tags(self):
        """TEST 15: ListTagsOfResource - List table tags"""
        # Get table ARN
        result = self.run_command([
            "aws", "dynamodb", "describe-table",
            "--table-name", self.TABLE_NAME
        ])
        table_arn = json.loads(result.stdout)["Table"]["TableArn"]

        result = self.run_command([
            "aws", "dynamodb", "list-tags-of-resource",
            "--resource-arn", table_arn
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("Tags", output)

    def test_16_tag_resource(self):
        """TEST 16: TagResource - Add tags to table"""
        # Get table ARN
        result = self.run_command([
            "aws", "dynamodb", "describe-table",
            "--table-name", self.TABLE_NAME
        ])
        table_arn = json.loads(result.stdout)["Table"]["TableArn"]

        result = self.run_command([
            "aws", "dynamodb", "tag-resource",
            "--resource-arn", table_arn,
            "--tags", "Key=NewTag,Value=NewValue"
        ])
        self.assertEqual(result.returncode, 0)

    def test_17_delete_table(self):
        """TEST 17: DeleteTable - Delete DynamoDB table"""
        result = self.run_command([
            "aws", "dynamodb", "delete-table",
            "--table-name", self.TABLE_NAME
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("TableDescription", output)

    def test_18_verify_table_deleted(self):
        """TEST 18: Verify table is deleted"""
        time.sleep(2)
        result = self.run_command([
            "aws", "dynamodb", "list-tables"
        ])
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertNotIn(self.TABLE_NAME, output.get("TableNames", []))


if __name__ == "__main__":
    unittest.main(verbosity=2)
