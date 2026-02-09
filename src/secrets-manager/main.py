"""
AWS Secrets Manager Implementation
Supports secret creation, retrieval, update, deletion, and versioning
Uses SQLite for persistence and base64 for basic encryption
"""

import json
import time
import uuid
import logging
import sqlite3
import custom_logger
import os
import base64
from contextlib import contextmanager
from typing import Optional, Dict, List, Any
from flask import Flask, request, jsonify, Response

logger = logging.getLogger(__name__)

ACCOUNT_ID = "456645664566"
REGION = "ap-southeast-2"

app = Flask(__name__)

DB_PATH = os.getenv("STORAGE_PATH", "/data") + "/secrets_manager.db"


class SecretsManagerException(Exception):
    """Base exception for Secrets Manager errors"""

    def __init__(self, error_type: str, message: str):
        self.error_type = error_type
        self.message = message
        super().__init__(message)


class ResourceNotFoundException(SecretsManagerException):
    """Secret not found exception"""

    def __init__(self, message: str):
        super().__init__("ResourceNotFoundException", message)


class InvalidParameterException(SecretsManagerException):
    """Invalid parameter exception"""

    def __init__(self, message: str):
        super().__init__("InvalidParameterException", message)


class InvalidRequestException(SecretsManagerException):
    """Invalid request exception"""

    def __init__(self, message: str):
        super().__init__("InvalidRequestException", message)


class ResourceExistsException(SecretsManagerException):
    """Resource already exists exception"""

    def __init__(self, message: str):
        super().__init__("ResourceExistsException", message)


class SecretsManagerDatabase:
    """Manages Secrets Manager data in SQLite using Database class"""

    def __init__(self):
        """Initialize Secrets Manager database"""
        self.db_path = DB_PATH
        self._init_database()
        logger.info(f"SecretsManagerDatabase initialized at {DB_PATH}")

    def _init_database(self):
        """Create tables if they don't exist"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Secrets table - stores secret metadata
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    secret_name TEXT PRIMARY KEY,
                    description TEXT,
                    kms_key_id TEXT,
                    created_date INTEGER NOT NULL,
                    last_updated_date INTEGER NOT NULL,
                    last_accessed_date INTEGER,
                    deleted_date INTEGER,
                    tags TEXT
                )
            """
            )

            # Secret versions table - stores actual secret values with versioning
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS secret_versions (
                    secret_name TEXT NOT NULL,
                    version_id TEXT NOT NULL,
                    secret_string TEXT,
                    secret_binary TEXT,
                    version_stages TEXT NOT NULL,
                    created_date INTEGER NOT NULL,
                    PRIMARY KEY (secret_name, version_id),
                    FOREIGN KEY (secret_name) REFERENCES secrets(secret_name) ON DELETE CASCADE
                )
            """
            )

            # Indexes for faster lookups
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_secret_versions_name
                ON secret_versions(secret_name)
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_secret_versions_stages
                ON secret_versions(secret_name, version_stages)
            """
            )

            conn.commit()
            logger.info("Secrets Manager database tables initialized")

    @contextmanager
    def _get_connection(self):
        """Get thread-safe database connection with context manager"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _encode_secret(self, value: str) -> str:
        """Encode secret value using base64"""
        return base64.b64encode(value.encode("utf-8")).decode("utf-8")

    def _decode_secret(self, encoded_value: str) -> str:
        """Decode secret value from base64"""
        return base64.b64decode(encoded_value.encode("utf-8")).decode("utf-8")

    def create_secret(
        self,
        secret_name: str,
        secret_string: Optional[str] = None,
        secret_binary: Optional[bytes] = None,
        description: Optional[str] = None,
        kms_key_id: Optional[str] = None,
        tags: Optional[List[Dict]] = None,
    ) -> Dict:
        """
        Create a new secret

        Args:
            secret_name: Name of the secret
            secret_string: Secret value as string (JSON or plain text)
            secret_binary: Secret value as binary
            description: Secret description
            kms_key_id: KMS key ID (not used yet)
            tags: List of tags

        Returns:
            Dict with ARN, Name, and VersionId

        Raises:
            ResourceExistsException: If secret already exists
            InvalidParameterException: If invalid parameters provided
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if secret already exists
            cursor.execute(
                "SELECT secret_name FROM secrets WHERE secret_name = ? AND deleted_date IS NULL",
                (secret_name,),
            )
            if cursor.fetchone():
                raise ResourceExistsException(
                    f"A resource with the ID or name '{secret_name}' already exists."
                )

            # Validate that either secret_string or secret_binary is provided
            if not secret_string and not secret_binary:
                raise InvalidParameterException(
                    "You must provide either SecretString or SecretBinary."
                )

            if secret_string and secret_binary:
                raise InvalidParameterException(
                    "You can't provide both SecretString and SecretBinary."
                )

            now = int(time.time())
            version_id = str(uuid.uuid4())

            # Encode the secret value
            encoded_string = None
            encoded_binary = None
            if secret_string:
                encoded_string = self._encode_secret(secret_string)
            if secret_binary:
                encoded_binary = secret_binary

            # Create secret metadata
            cursor.execute(
                """
                INSERT INTO secrets
                (secret_name, description, kms_key_id, created_date, last_updated_date, tags)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    secret_name,
                    description,
                    kms_key_id,
                    now,
                    now,
                    json.dumps(tags) if tags else None,
                ),
            )

            # Create initial version with AWSCURRENT stage
            cursor.execute(
                """
                INSERT INTO secret_versions
                (secret_name, version_id, secret_string, secret_binary, version_stages, created_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    secret_name,
                    version_id,
                    encoded_string,
                    encoded_binary,
                    json.dumps(["AWSCURRENT"]),
                    now,
                ),
            )

            conn.commit()

            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}-{version_id[:6]}"

            logger.info(f"Created secret: {secret_name} with version {version_id}")

            return {
                "ARN": arn,
                "Name": secret_name,
                "VersionId": version_id,
            }

    def get_secret_value(
        self,
        secret_name: str,
        version_id: Optional[str] = None,
        version_stage: Optional[str] = None,
    ) -> Dict:
        """
        Retrieve a secret value

        Args:
            secret_name: Name of the secret
            version_id: Specific version ID to retrieve
            version_stage: Version stage (defaults to AWSCURRENT)

        Returns:
            Dict with secret details

        Raises:
            ResourceNotFoundException: If secret not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if secret exists and is not deleted
            cursor.execute(
                "SELECT * FROM secrets WHERE secret_name = ? AND deleted_date IS NULL",
                (secret_name,),
            )
            secret = cursor.fetchone()
            if not secret:
                raise ResourceNotFoundException(
                    f"Secrets Manager can't find the specified secret: {secret_name}"
                )

            # Update last accessed date
            cursor.execute(
                "UPDATE secrets SET last_accessed_date = ? WHERE secret_name = ?",
                (int(time.time()), secret_name),
            )
            conn.commit()

            # Determine which version to retrieve
            if version_id:
                # Get specific version
                cursor.execute(
                    """
                    SELECT * FROM secret_versions
                    WHERE secret_name = ? AND version_id = ?
                """,
                    (secret_name, version_id),
                )
            else:
                # Get version by stage (default AWSCURRENT)
                stage = version_stage or "AWSCURRENT"
                cursor.execute(
                    """
                    SELECT * FROM secret_versions
                    WHERE secret_name = ? AND version_stages LIKE ?
                """,
                    (secret_name, f'%"{stage}"%'),
                )

            version = cursor.fetchone()
            if not version:
                raise ResourceNotFoundException(
                    f"Secrets Manager can't find the specified secret version"
                )

            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}-{version['version_id'][:6]}"

            result = {
                "ARN": arn,
                "Name": secret_name,
                "VersionId": version["version_id"],
                "VersionStages": json.loads(version["version_stages"]),
                "CreatedDate": version["created_date"],
            }

            # Decode and return the secret value
            if version["secret_string"]:
                result["SecretString"] = self._decode_secret(version["secret_string"])
            if version["secret_binary"]:
                result["SecretBinary"] = version["secret_binary"]

            return result

    def update_secret(
        self,
        secret_name: str,
        secret_string: Optional[str] = None,
        secret_binary: Optional[bytes] = None,
        description: Optional[str] = None,
        kms_key_id: Optional[str] = None,
    ) -> Dict:
        """
        Update a secret value (creates new version)

        Args:
            secret_name: Name of the secret
            secret_string: New secret value as string
            secret_binary: New secret value as binary
            description: Updated description
            kms_key_id: Updated KMS key ID

        Returns:
            Dict with ARN, Name, and VersionId

        Raises:
            ResourceNotFoundException: If secret not found
            InvalidParameterException: If invalid parameters provided
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if secret exists and is not deleted
            cursor.execute(
                "SELECT * FROM secrets WHERE secret_name = ? AND deleted_date IS NULL",
                (secret_name,),
            )
            secret = cursor.fetchone()
            if not secret:
                raise ResourceNotFoundException(
                    f"Secrets Manager can't find the specified secret: {secret_name}"
                )

            # Validate parameters
            if secret_string and secret_binary:
                raise InvalidParameterException(
                    "You can't provide both SecretString and SecretBinary."
                )

            now = int(time.time())
            new_version_id = str(uuid.uuid4())

            # Update secret metadata if provided
            if description is not None or kms_key_id is not None:
                updates = []
                params = []
                if description is not None:
                    updates.append("description = ?")
                    params.append(description)
                if kms_key_id is not None:
                    updates.append("kms_key_id = ?")
                    params.append(kms_key_id)
                updates.append("last_updated_date = ?")
                params.append(now)
                params.append(secret_name)

                cursor.execute(
                    f"UPDATE secrets SET {', '.join(updates)} WHERE secret_name = ?",
                    params,
                )

            # If secret value is being updated
            if secret_string or secret_binary:
                # Move AWSCURRENT to AWSPREVIOUS for existing version
                cursor.execute(
                    """
                    SELECT version_id, version_stages FROM secret_versions
                    WHERE secret_name = ? AND version_stages LIKE ?
                """,
                    (secret_name, '%"AWSCURRENT"%'),
                )
                current_version = cursor.fetchone()

                if current_version:
                    # Update previous version to AWSPREVIOUS
                    cursor.execute(
                        """
                        UPDATE secret_versions
                        SET version_stages = ?
                        WHERE secret_name = ? AND version_id = ?
                    """,
                        (
                            json.dumps(["AWSPREVIOUS"]),
                            secret_name,
                            current_version["version_id"],
                        ),
                    )

                # Encode the new secret value
                encoded_string = None
                encoded_binary = None
                if secret_string:
                    encoded_string = self._encode_secret(secret_string)
                if secret_binary:
                    encoded_binary = secret_binary

                # Create new version with AWSCURRENT stage
                cursor.execute(
                    """
                    INSERT INTO secret_versions
                    (secret_name, version_id, secret_string, secret_binary, version_stages, created_date)
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (
                        secret_name,
                        new_version_id,
                        encoded_string,
                        encoded_binary,
                        json.dumps(["AWSCURRENT"]),
                        now,
                    ),
                )

                # Update last_updated_date
                cursor.execute(
                    "UPDATE secrets SET last_updated_date = ? WHERE secret_name = ?",
                    (now, secret_name),
                )

            conn.commit()

            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}-{new_version_id[:6]}"

            logger.info(f"Updated secret: {secret_name} with version {new_version_id}")

            return {
                "ARN": arn,
                "Name": secret_name,
                "VersionId": new_version_id,
            }

    def update_secret_version_stage(
        self,
        secret_name: str,
        version_stage: str,
        move_to_version_id: Optional[str] = None,
        remove_from_version_id: Optional[str] = None,
    ) -> Dict:
        """
        Update version stages for a secret

        Args:
            secret_name: Name of the secret
            version_stage: The staging label to modify
            move_to_version_id: Version ID to move the stage to
            remove_from_version_id: Version ID to remove the stage from

        Returns:
            Dict with ARN, Name, and VersionId

        Raises:
            ResourceNotFoundException: If secret or version not found
            InvalidParameterException: If invalid parameters provided
            InvalidRequestException: If operation would violate constraints
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if secret exists
            cursor.execute(
                "SELECT secret_name FROM secrets WHERE secret_name = ? AND deleted_date IS NULL",
                (secret_name,),
            )
            if not cursor.fetchone():
                raise ResourceNotFoundException(f"Secret '{secret_name}' not found.")

            # Validate that at least one action is specified
            if not move_to_version_id and not remove_from_version_id:
                raise InvalidParameterException(
                    "You must specify either MoveToVersionId or RemoveFromVersionId."
                )

            # If moving, validate the target version exists
            if move_to_version_id:
                cursor.execute(
                    "SELECT version_id, version_stages FROM secret_versions WHERE secret_name = ? AND version_id = ?",
                    (secret_name, move_to_version_id),
                )
                target_version = cursor.fetchone()
                if not target_version:
                    raise ResourceNotFoundException(
                        f"Version '{move_to_version_id}' not found for secret '{secret_name}'."
                    )

            # If removing from specific version, validate it exists
            if remove_from_version_id:
                cursor.execute(
                    "SELECT version_id, version_stages FROM secret_versions WHERE secret_name = ? AND version_id = ?",
                    (secret_name, remove_from_version_id),
                )
                source_version = cursor.fetchone()
                if not source_version:
                    raise ResourceNotFoundException(
                        f"Version '{remove_from_version_id}' not found for secret '{secret_name}'."
                    )

                # Check if the version actually has this stage
                stages = json.loads(source_version["version_stages"])
                if version_stage not in stages:
                    raise InvalidRequestException(
                        f"Version '{remove_from_version_id}' does not have stage '{version_stage}'."
                    )

            # Handle AWSCURRENT special case - find current version if not specified
            current_version_id = None
            if version_stage == "AWSCURRENT" and not remove_from_version_id:
                cursor.execute(
                    "SELECT version_id, version_stages FROM secret_versions WHERE secret_name = ?",
                    (secret_name,),
                )
                for row in cursor.fetchall():
                    stages = json.loads(row["version_stages"])
                    if "AWSCURRENT" in stages:
                        current_version_id = row["version_id"]
                        break

            # Remove stage from source version
            if remove_from_version_id or current_version_id:
                version_to_remove_from = remove_from_version_id or current_version_id
                cursor.execute(
                    "SELECT version_stages FROM secret_versions WHERE secret_name = ? AND version_id = ?",
                    (secret_name, version_to_remove_from),
                )
                row = cursor.fetchone()
                if row:
                    stages = json.loads(row["version_stages"])
                    if version_stage in stages:
                        stages.remove(version_stage)

                        # If this was AWSCURRENT being moved, add AWSPREVIOUS to old version
                        if version_stage == "AWSCURRENT" and move_to_version_id:
                            if "AWSPREVIOUS" not in stages:
                                stages.append("AWSPREVIOUS")

                        cursor.execute(
                            "UPDATE secret_versions SET version_stages = ? WHERE secret_name = ? AND version_id = ?",
                            (
                                json.dumps(stages),
                                secret_name,
                                version_to_remove_from,
                            ),
                        )

            # Add stage to target version
            if move_to_version_id:
                cursor.execute(
                    "SELECT version_stages FROM secret_versions WHERE secret_name = ? AND version_id = ?",
                    (secret_name, move_to_version_id),
                )
                row = cursor.fetchone()
                stages = json.loads(row["version_stages"])

                if version_stage not in stages:
                    stages.append(version_stage)

                # If adding AWSCURRENT, remove AWSPREVIOUS if present
                if version_stage == "AWSCURRENT" and "AWSPREVIOUS" in stages:
                    stages.remove("AWSPREVIOUS")

                cursor.execute(
                    "UPDATE secret_versions SET version_stages = ? WHERE secret_name = ? AND version_id = ?",
                    (json.dumps(stages), secret_name, move_to_version_id),
                )

            # Update last_updated_date
            cursor.execute(
                "UPDATE secrets SET last_updated_date = ? WHERE secret_name = ?",
                (int(time.time()), secret_name),
            )

            conn.commit()

            # Build ARN
            cursor.execute(
                "SELECT version_id FROM secret_versions WHERE secret_name = ? ORDER BY created_date DESC LIMIT 1",
                (secret_name,),
            )
            latest = cursor.fetchone()
            version_suffix = latest["version_id"] if latest else "??????"
            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}-{version_suffix}"

            return {
                "ARN": arn,
                "Name": secret_name,
                "VersionId": move_to_version_id or remove_from_version_id,
            }

    def delete_secret(
        self,
        secret_name: str,
        recovery_window_in_days: Optional[int] = 30,
        force_delete: bool = False,
    ) -> Dict:
        """
        Delete a secret

        Args:
            secret_name: Name of the secret
            recovery_window_in_days: Days before permanent deletion
            force_delete: Force immediate deletion

        Returns:
            Dict with ARN, Name, and DeletionDate

        Raises:
            ResourceNotFoundException: If secret not found
            InvalidParameterException: If invalid parameters provided
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if secret exists and is not already deleted
            cursor.execute(
                "SELECT * FROM secrets WHERE secret_name = ? AND deleted_date IS NULL",
                (secret_name,),
            )
            secret = cursor.fetchone()
            if not secret:
                raise ResourceNotFoundException(
                    f"Secrets Manager can't find the specified secret: {secret_name}"
                )

            now = int(time.time())

            if force_delete:
                # Immediate deletion
                cursor.execute(
                    "DELETE FROM secret_versions WHERE secret_name = ?", (secret_name,)
                )
                cursor.execute(
                    "DELETE FROM secrets WHERE secret_name = ?", (secret_name,)
                )
                deletion_date = now
            else:
                # Scheduled deletion
                if recovery_window_in_days is not None and (
                    recovery_window_in_days < 7 or recovery_window_in_days > 30
                ):
                    raise InvalidParameterException(
                        "Recovery window must be between 7 and 30 days."
                    )

                recovery_window = recovery_window_in_days or 30
                deletion_date = now + (
                    recovery_window * 86400
                )  # Convert days to seconds

                cursor.execute(
                    "UPDATE secrets SET deleted_date = ? WHERE secret_name = ?",
                    (deletion_date, secret_name),
                )

            conn.commit()

            # Get the latest version ID for ARN
            cursor.execute(
                """
                SELECT version_id FROM secret_versions
                WHERE secret_name = ?
                ORDER BY created_date DESC
                LIMIT 1
            """,
                (secret_name,),
            )
            latest_version = cursor.fetchone()
            version_suffix = (
                latest_version["version_id"][:6] if latest_version else "??????"
            )

            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}-{version_suffix}"

            logger.info(f"Deleted secret: {secret_name}")

            return {
                "ARN": arn,
                "Name": secret_name,
                "DeletionDate": deletion_date,
            }

    def restore_secret(self, secret_name: str) -> Dict:
        """
        Restore a deleted secret (cancel scheduled deletion)

        Args:
            secret_name: Name of the secret to restore

        Returns:
            Dict with ARN and Name

        Raises:
            ResourceNotFoundException: If secret not found or not scheduled for deletion
            InvalidRequestException: If secret deletion window has passed
        """
        # Purge if expired (this will delete it if past recovery window)
        if self._purge_if_expired(secret_name):
            raise ResourceNotFoundException(
                f"Secrets Manager can't find the specified secret: {secret_name}"
            )

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if secret exists
            cursor.execute(
                "SELECT deleted_date FROM secrets WHERE secret_name = ?", (secret_name,)
            )
            secret = cursor.fetchone()

            if not secret:
                raise ResourceNotFoundException(
                    f"Secrets Manager can't find the specified secret: {secret_name}"
                )

            if not secret["deleted_date"]:
                raise InvalidRequestException(
                    f"The secret {secret_name} is not scheduled for deletion."
                )

            # Check if still within recovery window
            now = int(time.time())
            if now >= secret["deleted_date"]:
                raise InvalidRequestException(
                    f"The secret {secret_name} recovery window has expired."
                )

            # Clear the deletion date to restore the secret
            cursor.execute(
                "UPDATE secrets SET deleted_date = NULL WHERE secret_name = ?",
                (secret_name,),
            )
            conn.commit()

            # Get version for ARN
            cursor.execute(
                "SELECT version_id FROM secret_versions WHERE secret_name = ? ORDER BY created_date DESC LIMIT 1",
                (secret_name,),
            )
            version = cursor.fetchone()
            version_suffix = version["version_id"] if version else "??????"
            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}-{version_suffix}"

            logger.info(f"Restored secret: {secret_name}")

            return {"ARN": arn, "Name": secret_name}

    def list_secrets(
        self,
        max_results: int = 100,
        next_token: Optional[str] = None,
    ) -> Dict:
        """
        List all secrets (includes secrets scheduled for deletion, but not purged ones)

        Args:
            max_results: Maximum number of results
            next_token: Pagination token TODO

        Returns:
            Dict with SecretList and NextToken
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Get all secrets (including deleted ones)
            # Purged secrets are automatically removed by CASCADE DELETE
            cursor.execute(
                """
                SELECT * FROM secrets
                ORDER BY secret_name
                LIMIT ?
            """,
                (max_results + 1,),  # Get one extra to check if there are more
            )

            secrets = cursor.fetchall()
            secret_list = []

            for secret in secrets[:max_results]:
                # Get current version info
                cursor.execute(
                    """
                    SELECT version_id, version_stages, created_date FROM secret_versions
                    WHERE secret_name = ? AND version_stages LIKE ?
                    ORDER BY created_date DESC
                    LIMIT 1
                """,
                    (secret["secret_name"], '%"AWSCURRENT"%'),
                )
                version = cursor.fetchone()

                version_suffix = version["version_id"] if version else "??????"
                arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret['secret_name']}-{version_suffix}"

                secret_info = {
                    "ARN": arn,
                    "Name": secret["secret_name"],
                    "LastChangedDate": secret["last_updated_date"],
                    "LastAccessedDate": secret["last_accessed_date"],
                    "CreatedDate": secret["created_date"],
                }

                if secret["description"]:
                    secret_info["Description"] = secret["description"]
                if secret["kms_key_id"]:
                    secret_info["KmsKeyId"] = secret["kms_key_id"]
                if secret["tags"]:
                    secret_info["Tags"] = json.loads(secret["tags"])
                if secret["deleted_date"]:
                    secret_info["DeletedDate"] = secret["deleted_date"]

                secret_list.append(secret_info)

            result = {"SecretList": secret_list}

            # Add NextToken if there are more results
            if len(secrets) > max_results:
                result["NextToken"] = str(
                    max_results
                )  # Simple pagination token, use max * page# for next batch

            return result

    def _purge_if_expired(self, secret_name: str) -> bool:
        """
        Check if a secret is past its deletion window and purge it if so.
        This implements lazy deletion - secrets are purged when accessed.

        Args:
            secret_name: Name of the secret to check

        Returns:
            True if secret was purged, False otherwise
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Get secret with deletion info
            cursor.execute(
                "SELECT deleted_date FROM secrets WHERE secret_name = ?", (secret_name,)
            )
            secret = cursor.fetchone()

            if not secret or not secret["deleted_date"]:
                return False

            # Calculate deletion deadline (deleted_date is the future deletion date)
            # If current time is past deletion date, purge it
            now = int(time.time())
            if now >= secret["deleted_date"]:
                # Permanently delete the secret and all its versions
                cursor.execute(
                    "DELETE FROM secrets WHERE secret_name = ?", (secret_name,)
                )
                conn.commit()
                logger.info(f"Purged expired secret: {secret_name}")
                return True

            return False

    def secret_exists(self, secret_name: str) -> bool:
        """
        Check if a secret exists and is not marked deleted (purges if expired).

        Args:
            secret_name: Name of the secret to check.

        Returns:
            True if the secret exists and is active (not deleted), False otherwise.
        """
        # Purge if expired first
        self._purge_if_expired(secret_name)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 1 FROM secrets
                WHERE secret_name = ?
                LIMIT 1
                """,
                (secret_name,),
            )
            return cursor.fetchone() is not None

    def describe_secret(self, secret_name: str) -> Dict:
        """
        Get secret metadata without retrieving the secret value

        Args:
            secret_name: Name of the secret

        Returns:
            Dict with secret metadata

        Raises:
            ResourceNotFoundException: If secret not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT * FROM secrets WHERE secret_name = ? AND deleted_date IS NULL",
                (secret_name,),
            )
            secret = cursor.fetchone()

            if not secret:
                raise ResourceNotFoundException(
                    f"Secrets Manager can't find the specified secret: {secret_name}"
                )

            # Get version information
            cursor.execute(
                """
                SELECT version_id, version_stages FROM secret_versions
                WHERE secret_name = ?
                ORDER BY created_date DESC
            """,
                (secret_name,),
            )
            versions = cursor.fetchall()

            version_ids_to_stages = {}
            for v in versions:
                version_ids_to_stages[v["version_id"]] = json.loads(v["version_stages"])

            latest_version = versions[0] if versions else None
            version_suffix = (
                latest_version["version_id"][:6] if latest_version else "??????"
            )
            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}-{version_suffix}"

            result = {
                "ARN": arn,
                "Name": secret_name,
                "CreatedDate": secret["created_date"],
                "LastChangedDate": secret["last_updated_date"],
                "VersionIdsToStages": version_ids_to_stages,
            }

            if secret["description"]:
                result["Description"] = secret["description"]
            if secret["kms_key_id"]:
                result["KmsKeyId"] = secret["kms_key_id"]
            if secret["last_accessed_date"]:
                result["LastAccessedDate"] = secret["last_accessed_date"]
            if secret["deleted_date"]:
                result["DeletedDate"] = secret["deleted_date"]
            if secret["tags"]:
                result["Tags"] = json.loads(secret["tags"])

            return result

    def list_secret_version_ids(
        self, secret_name: str, max_results: int = 100, include_deprecated: bool = True
    ) -> Dict:
        """
        List all version IDs for a secret

        Args:
            secret_name: Name of the secret
            max_results: Maximum number of results
            include_deprecated: Include versions without staging labels

        Returns:
            Dict with version information including VersionIdsToStages

        Raises:
            ResourceNotFoundException: If secret not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if secret exists and is not deleted
            cursor.execute(
                "SELECT secret_name FROM secrets WHERE secret_name = ? AND deleted_date IS NULL",
                (secret_name,),
            )
            if not cursor.fetchone():
                raise ResourceNotFoundException(
                    f"Secrets Manager can't find the specified secret: {secret_name}"
                )

            # Get all versions
            cursor.execute(
                """
                SELECT version_id, version_stages, created_date
                FROM secret_versions
                WHERE secret_name = ?
                ORDER BY created_date DESC
                LIMIT ?
            """,
                (secret_name, max_results),
            )
            versions = cursor.fetchall()

            # Build version list
            version_list = []
            for v in versions:
                stages = json.loads(v["version_stages"])

                # Skip deprecated versions if requested
                if not include_deprecated and len(stages) == 0:
                    continue

                version_info = {
                    "VersionId": v["version_id"],
                    "VersionStages": stages,
                    "CreatedDate": v["created_date"],
                }
                version_list.append(version_info)

            # Get latest version for ARN
            cursor.execute(
                "SELECT version_id FROM secret_versions WHERE secret_name = ? ORDER BY created_date DESC LIMIT 1",
                (secret_name,),
            )
            latest = cursor.fetchone()
            version_suffix = latest["version_id"] if latest else "??????"
            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}-{version_suffix}"

            return {
                "ARN": arn,
                "Name": secret_name,
                "Versions": version_list,
            }

    def put_secret_value(
        self,
        secret_name: str,
        secret_string: Optional[str] = None,
        secret_binary: Optional[bytes] = None,
        version_stages: Optional[List[str]] = None,
    ) -> Dict:
        """
        Create a new version of a secret or restore a previous version to current.
        This is the AWS-native way to "restore" - by making a previous version current.

        Args:
            secret_name: Name of the secret
            secret_string: Secret value as string
            secret_binary: Secret value as binary
            version_stages: List of staging labels (default ["AWSCURRENT"])

        Returns:
            Dict with ARN, Name, VersionId, and VersionStages

        Raises:
            ResourceNotFoundException: If secret not found
            InvalidParameterException: If invalid parameters provided
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if secret exists and is not deleted
            cursor.execute(
                "SELECT * FROM secrets WHERE secret_name = ? AND deleted_date IS NULL",
                (secret_name,),
            )
            secret = cursor.fetchone()
            if not secret:
                raise ResourceNotFoundException(
                    f"Secrets Manager can't find the specified secret: {secret_name}"
                )

            # Validate secret value provided
            if not secret_string and not secret_binary:
                raise InvalidParameterException(
                    "You must provide either SecretString or SecretBinary."
                )

            if secret_string and secret_binary:
                raise InvalidParameterException(
                    "You can't provide both SecretString and SecretBinary."
                )

            # Set default stages if not provided
            if not version_stages:
                version_stages = ["AWSCURRENT"]

            # If AWSCURRENT is in the stages, move it from the old version
            if "AWSCURRENT" in version_stages:
                # Find current AWSCURRENT version
                cursor.execute(
                    "SELECT version_id, version_stages FROM secret_versions WHERE secret_name = ?",
                    (secret_name,),
                )
                for row in cursor.fetchall():
                    stages = json.loads(row["version_stages"])
                    if "AWSCURRENT" in stages:
                        # Remove AWSCURRENT and add AWSPREVIOUS
                        stages.remove("AWSCURRENT")
                        if "AWSPREVIOUS" not in stages:
                            stages.append("AWSPREVIOUS")
                        cursor.execute(
                            "UPDATE secret_versions SET version_stages = ? WHERE secret_name = ? AND version_id = ?",
                            (json.dumps(stages), secret_name, row["version_id"]),
                        )
                        break

            # Create new version
            now = int(time.time())
            version_id = str(uuid.uuid4())

            # Encode the secret value
            encoded_string = None
            encoded_binary = None
            if secret_string:
                encoded_string = self._encode_secret(secret_string)
            if secret_binary:
                encoded_binary = secret_binary

            cursor.execute(
                """
                INSERT INTO secret_versions
                (secret_name, version_id, secret_string, secret_binary, version_stages, created_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    secret_name,
                    version_id,
                    encoded_string,
                    encoded_binary,
                    json.dumps(version_stages),
                    now,
                ),
            )

            # Update last_updated_date
            cursor.execute(
                "UPDATE secrets SET last_updated_date = ? WHERE secret_name = ?",
                (now, secret_name),
            )

            conn.commit()

            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}-{version_id[:6]}"

            logger.info(
                f"Created new secret version for '{secret_name}' with stages {version_stages}"
            )

            return {
                "ARN": arn,
                "Name": secret_name,
                "VersionId": version_id,
                "VersionStages": version_stages,
            }


class SecretsManager:
    """Container for Secrets Manager operations"""

    def __init__(self):
        """Initialize Secrets Manager container"""
        self.db = SecretsManagerDatabase()
        logger.info("SecretsManagerContainer initialized")

    def create_secret(self, params: Dict) -> Dict:
        """Create a new secret"""
        secret_name = params.get("Name")
        if not secret_name:
            raise InvalidParameterException("Secret name is required")

        if self.db.secret_exists(secret_name):
            raise ResourceExistsException(
                f"A resource with the name {secret_name} already exists."
            )

        return self.db.create_secret(
            secret_name=secret_name,
            secret_string=params.get("SecretString"),
            secret_binary=params.get("SecretBinary"),
            description=params.get("Description"),
            kms_key_id=params.get("KmsKeyId"),
            tags=params.get("Tags"),
        )

    def get_secret_value(self, params: Dict) -> Dict:
        """Get secret value"""
        secret_id = params.get("SecretId")
        if not secret_id:
            raise InvalidParameterException("SecretId is required")

        result = self.db.get_secret_value(
            secret_name=secret_id,
            version_id=params.get("VersionId"),
            version_stage=params.get("VersionStage"),
        )
        return result

    def update_secret(self, params: Dict) -> Dict:
        """Update a secret"""
        secret_id = params.get("SecretId")
        if not secret_id:
            raise InvalidParameterException("SecretId is required")

        return self.db.update_secret(
            secret_name=secret_id,
            secret_string=params.get("SecretString"),
            secret_binary=params.get("SecretBinary"),
            description=params.get("Description"),
            kms_key_id=params.get("KmsKeyId"),
        )

    def update_secret_version_stage(self, params: Dict) -> Dict:
        """Update version stages for a secret"""
        secret_id = params.get("SecretId")
        if not secret_id:
            raise InvalidParameterException("SecretId is required")

        version_stage = params.get("VersionStage")
        if not version_stage:
            raise InvalidParameterException("VersionStage is required")

        return self.db.update_secret_version_stage(
            secret_name=secret_id,
            version_stage=version_stage,
            move_to_version_id=params.get("MoveToVersionId"),
            remove_from_version_id=params.get("RemoveFromVersionId"),
        )

    def delete_secret(self, params: Dict) -> Dict:
        """Delete a secret"""
        secret_id = params.get("SecretId")
        if not secret_id:
            raise InvalidParameterException("SecretId is required")

        return self.db.delete_secret(
            secret_name=secret_id,
            recovery_window_in_days=params.get("RecoveryWindowInDays"),
            force_delete=params.get("ForceDeleteWithoutRecovery", False),
        )

    def restore_secret(self, params: Dict) -> Dict:
        """Restore a secret"""
        secret_id = params.get("SecretId")
        if not secret_id:
            raise InvalidParameterException("SecretId is required")

        return self.db.restore_secret(secret_name=secret_id)

    def list_secrets(self, params: Dict) -> Dict:
        """List all secrets"""
        return self.db.list_secrets(
            max_results=params.get("MaxResults", 100),
            next_token=params.get("NextToken"),
        )

    def describe_secret(self, params: Dict) -> Dict:
        """Describe secret metadata"""
        secret_id = params.get("SecretId")
        if not secret_id:
            raise InvalidParameterException("SecretId is required")

        return self.db.describe_secret(secret_name=secret_id)

    def list_secret_version_ids(self, params: Dict) -> Dict:
        """List all version IDs for a secret"""
        secret_id = params.get("SecretId")
        if not secret_id:
            raise InvalidParameterException("SecretId is required")

        return self.db.list_secret_version_ids(
            secret_name=secret_id,
            max_results=params.get("MaxResults", 100),
            include_deprecated=params.get("IncludeDeprecated", True),
        )

    def put_secret_value(self, params: Dict) -> Dict:
        """Put a new secret value (creates new version)"""
        secret_id = params.get("SecretId")
        if not secret_id:
            raise InvalidParameterException("SecretId is required")

        return self.db.put_secret_value(
            secret_name=secret_id,
            secret_string=params.get("SecretString"),
            secret_binary=params.get("SecretBinary"),
            version_stages=params.get("VersionStages"),
        )


# Flask routes
secrets_manager = SecretsManager()


def error_response(error_type: str, message: str) -> Dict:
    """Format error response in AWS format"""
    return {
        "__type": error_type,
        "message": message,
    }


@app.route("/", methods=["POST"])
def handle_request():
    """Main request handler for Secrets Manager operations"""
    try:
        # Get the operation from X-Amz-Target header
        target = request.headers.get("X-Amz-Target", "")
        operation = target.split(".")[-1] if "." in target else None

        if not operation:
            return (
                jsonify(error_response("InvalidAction", "Missing X-Amz-Target header")),
                400,
            )

        # Get request body
        try:
            params = request.get_json(force=True) or {}
        except Exception:
            logger.error(f"Invalid JSON in request body: {request.data}")
            return (
                jsonify(
                    error_response(
                        "InvalidRequestException", "Invalid JSON in request body"
                    )
                ),
                400,
            )

        logger.info(f"Secrets Manager operation: {operation}")

        # Route to appropriate handler
        if operation == "CreateSecret":
            result = secrets_manager.create_secret(params)
            return jsonify(result), 200

        elif operation == "GetSecretValue":
            result = secrets_manager.get_secret_value(params)
            return jsonify(result), 200

        elif operation == "UpdateSecret":
            result = secrets_manager.update_secret(params)
            return jsonify(result), 200

        elif operation == "UpdateSecretVersionStage":
            result = secrets_manager.update_secret_version_stage(params)
            return jsonify(result), 200

        elif operation == "DeleteSecret":
            result = secrets_manager.delete_secret(params)
            return jsonify(result), 200

        elif operation == "RestoreSecret":
            result = secrets_manager.restore_secret(params)
            return jsonify(result), 200

        elif operation == "ListSecrets":
            result = secrets_manager.list_secrets(params)
            return jsonify(result), 200

        elif operation == "DescribeSecret":
            result = secrets_manager.describe_secret(params)
            return jsonify(result), 200

        elif operation == "ListSecretVersionIds":
            result = secrets_manager.list_secret_version_ids(params)
            return jsonify(result), 200

        elif operation == "PutSecretValue":
            result = secrets_manager.put_secret_value(params)
            return jsonify(result), 200

        else:
            return (
                jsonify(
                    error_response("InvalidAction", f"Unknown operation: {operation}")
                ),
                400,
            )

    except SecretsManagerException as e:
        logger.error(f"Secrets Manager error: {e.error_type} - {e.message}")
        return jsonify(error_response(e.error_type, e.message)), 400

    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        return jsonify(error_response("InternalServiceError", str(e))), 500


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy"}), 200


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    app.run(host="0.0.0.0", port=4566, debug=False)
