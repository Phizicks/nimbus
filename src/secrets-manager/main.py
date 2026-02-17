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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import urllib.request
import urllib.error

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

    # Class level encryption key cache to ensure consistency across instances
    _encryption_key_cache: Optional[bytes] = None

    def __init__(self):
        """Initialize Secrets Manager database"""
        self._init_database()  # Initialize database first
        self.encryption_key = self._get_encryption_key()  # Then get encryption key
        logger.info("SecretsManagerDatabase initialized")

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
                    rotation_enabled BOOLEAN DEFAULT FALSE,
                    rotation_lambda_arn TEXT,
                    rotation_rules TEXT,
                    last_rotated_date INTEGER,
                    rotation_status TEXT,
                    resource_policy TEXT,
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

            # Salt and secret table for encryption key. should only ever contain 1
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS salt_secret (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    salt BLOB NOT NULL,
                    secret BLOB NOT NULL,
                    created_date INTEGER NOT NULL
                )
            """
            )

            # Migrate existing old schema
            cursor = conn.cursor()

            # Check if rotation columns exist
            cursor.execute("PRAGMA table_info(secrets)")
            columns = [row[1] for row in cursor.fetchall()]

            # Add rotation columns if they don't exist
            if "rotation_enabled" not in columns:
                logger.info("Migrating database: adding rotation columns")
                cursor.execute(
                    "ALTER TABLE secrets ADD COLUMN rotation_enabled BOOLEAN DEFAULT FALSE"
                )

            if "rotation_lambda_arn" not in columns:
                cursor.execute(
                    "ALTER TABLE secrets ADD COLUMN rotation_lambda_arn TEXT"
                )

            if "rotation_rules" not in columns:
                cursor.execute("ALTER TABLE secrets ADD COLUMN rotation_rules TEXT")

            if "last_rotated_date" not in columns:
                cursor.execute(
                    "ALTER TABLE secrets ADD COLUMN last_rotated_date INTEGER"
                )

            if "rotation_status" not in columns:
                cursor.execute("ALTER TABLE secrets ADD COLUMN rotation_status TEXT")

            if "resource_policy" not in columns:
                cursor.execute("ALTER TABLE secrets ADD COLUMN resource_policy TEXT")

    @contextmanager
    def _get_connection(self):
        """Get thread-safe database connection with context manager"""
        # Get current database path (allows for test overrides)
        db_path = os.getenv("STORAGE_PATH", "/data") + "/secrets_manager.db"

        # Ensure the directory exists
        db_dir = os.path.dirname(db_path)
        os.makedirs(db_dir, exist_ok=True)

        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _get_encryption_key(self) -> bytes:
        """Generate or retrieve AES-256 existing encryption key from database"""
        # Check class-level cache first
        if SecretsManagerDatabase._encryption_key_cache is not None:
            return SecretsManagerDatabase._encryption_key_cache

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Try to get existing salt and secret - should only ever have 1
            cursor.execute("SELECT salt, secret FROM salt_secret WHERE id = 1")
            existing_encryption = cursor.fetchone()

            if existing_encryption:
                # Use existing salt and secret
                salt, secret = existing_encryption
            else:
                # Generate new random salt and secret
                salt = secrets.token_bytes(16)  # 128-bit salt
                secret = secrets.token_bytes(32)  # 256-bit secret
                created_date = int(time.time())

                # Store them in database
                cursor.execute(
                    "INSERT INTO salt_secret (id, salt, secret, created_date) VALUES (?, ?, ?, ?)",
                    (1, salt, secret, created_date),
                )
                conn.commit()
                logger.info("Generated and stored new encryption salt and secret")

            # Create encryption key using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits / 8
                salt=salt,
                iterations=100000,
                backend=default_backend(),
            )
            key = kdf.derive(secret)

            # Cache the key at class level
            SecretsManagerDatabase._encryption_key_cache = key
            return key

    def _encode_secret(self, value: str) -> str:
        """Encrypt secret value using AES-256"""
        iv = secrets.token_bytes(16)  # 128-bit IV
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()

        # Pad to block size
        padded_data = value.encode("utf-8")
        block_size = algorithms.AES.block_size // 8
        padding_len = block_size - (len(padded_data) % block_size)
        padded_data += bytes([padding_len]) * padding_len

        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        # Combine IV and encrypted data, base64 encode
        combined = iv + encrypted
        return base64.b64encode(combined).decode("utf-8")

    def _decode_secret(self, encoded_value: str) -> str:
        """Decrypt secret value using AES-256"""
        combined = base64.b64decode(encoded_value.encode("utf-8"))
        iv = combined[:16]
        encrypted = combined[16:]

        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(encrypted) + decryptor.finalize()

        # Remove padding
        padding_len = padded_data[-1]
        if padding_len > 16:  # Invalid padding
            raise ValueError("Invalid padding")
        return padded_data[:-padding_len].decode("utf-8")

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

    def _check_and_rotate_if_needed(self, secret_name: str):
        """Check if secret needs rotation and rotate if necessary"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT rotation_enabled, rotation_rules, last_rotated_date FROM secrets WHERE secret_name = ?",
                (secret_name,),
            )
            secret = cursor.fetchone()

            if not secret or "rotation_enabled" not in secret.keys():
                return

            rotation_rules = (
                json.loads(secret["rotation_rules"])
                if "rotation_rules" in secret
                else {}
            )
            days = rotation_rules.get("AutomaticallyAfterDays", 0)

            if days <= 0:
                return

            last_rotated = secret.get("last_rotated_date") or secret["created_date"]
            now = int(time.time())
            days_since_rotation = (now - last_rotated) / 86400

            if days_since_rotation >= days:
                logger.info(
                    f"Auto-rotating secret {secret_name} (last rotated {days_since_rotation:.1f} days ago)"
                )
                self.rotate_secret(secret_name=secret_name)

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

        # Check if rotation is due
        self._check_and_rotate_if_needed(secret_name)

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
                if (
                    "rotation_enabled" in secret
                    and secret["rotation_enabled"] is not None
                    and secret["rotation_enabled"]
                ):
                    secret_info["RotationEnabled"] = secret["rotation_enabled"]

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

            # Rotation fields - need to use .keys() to check if it exists - weird.
            if "rotation_enabled" in secret.keys() and secret["rotation_enabled"]:
                result["RotationEnabled"] = bool(secret["rotation_enabled"])
            if "rotation_lambda_arn" in secret.keys() and secret["rotation_lambda_arn"]:
                result["RotationLambdaARN"] = secret["rotation_lambda_arn"]
            if "rotation_rules" in secret.keys() and secret["rotation_rules"]:
                result["RotationRules"] = json.loads(secret["rotation_rules"])
            if "last_rotated_date" in secret.keys() and secret["last_rotated_date"]:
                result["LastRotatedDate"] = secret["last_rotated_date"]
            if "rotation_status" in secret.keys() and secret["rotation_status"]:
                result["RotationStatus"] = secret["rotation_status"]

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

    def put_resource_policy(self, secret_name: str, resource_policy: str) -> Dict:
        """Put resource policy for a secret"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if secret exists
            cursor.execute(
                "SELECT secret_name FROM secrets WHERE secret_name = ? AND deleted_date IS NULL",
                (secret_name,),
            )
            if not cursor.fetchone():
                raise ResourceNotFoundException(f"Secret '{secret_name}' not found.")

            # For now, just store the policy (no validation)
            cursor.execute(
                "UPDATE secrets SET resource_policy = ? WHERE secret_name = ?",
                (resource_policy, secret_name),
            )
            conn.commit()

            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}"
            return {"ARN": arn, "Name": secret_name}

    def get_resource_policy(self, secret_name: str) -> Dict:
        """Get resource policy for a secret"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT resource_policy FROM secrets WHERE secret_name = ? AND deleted_date IS NULL",
                (secret_name,),
            )
            secret = cursor.fetchone()

            if not secret:
                raise ResourceNotFoundException(f"Secret '{secret_name}' not found.")

            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}"
            result = {"ARN": arn, "Name": secret_name}

            if secret["resource_policy"]:
                result["ResourcePolicy"] = secret["resource_policy"]

            return result

    def delete_resource_policy(self, secret_name: str) -> Dict:
        """Delete resource policy for a secret"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT secret_name FROM secrets WHERE secret_name = ? AND deleted_date IS NULL",
                (secret_name,),
            )
            if not cursor.fetchone():
                raise ResourceNotFoundException(f"Secret '{secret_name}' not found.")

            cursor.execute(
                "UPDATE secrets SET resource_policy = NULL WHERE secret_name = ?",
                (secret_name,),
            )
            conn.commit()

            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}"
            return {"ARN": arn, "Name": secret_name}

    def configure_rotation(
        self, secret_name: str, rotation_lambda_arn: str, rotation_rules: Dict
    ) -> Dict:
        """Configure rotation for a secret"""
        if not secret_name:
            raise InvalidParameterException("Secret name is required")
        if not rotation_lambda_arn:
            raise InvalidParameterException("RotationLambdaARN is required")
        if not isinstance(rotation_rules, dict):
            raise InvalidParameterException("RotationRules must be a dictionary")

        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT secret_name FROM secrets WHERE secret_name = ? AND deleted_date IS NULL",
                (secret_name,),
            )
            if not cursor.fetchone():
                raise ResourceNotFoundException(f"Secret '{secret_name}' not found.")

            cursor.execute(
                """
                UPDATE secrets SET
                    rotation_enabled = TRUE,
                    rotation_lambda_arn = ?,
                    rotation_rules = ?,
                    rotation_status = 'Enabled'
                WHERE secret_name = ?
                """,
                (rotation_lambda_arn, json.dumps(rotation_rules), secret_name),
            )
            conn.commit()

            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}"
            return {"ARN": arn, "Name": secret_name}

    def cancel_rotate_secret(self, secret_name: str) -> Dict:
        """Cancel rotation for a secret"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT secret_name FROM secrets WHERE secret_name = ? AND deleted_date IS NULL",
                (secret_name,),
            )
            if not cursor.fetchone():
                raise ResourceNotFoundException(f"Secret '{secret_name}' not found.")

            cursor.execute(
                """
                UPDATE secrets SET
                    rotation_enabled = FALSE,
                    rotation_lambda_arn = NULL,
                    rotation_rules = NULL,
                    rotation_status = NULL
                WHERE secret_name = ?
                """,
                (secret_name,),
            )
            conn.commit()

            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}"
            return {"ARN": arn, "Name": secret_name}

    def get_rotation_policy(self, secret_name: str) -> Dict:
        """Get rotation policy for a secret"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT rotation_lambda_arn, rotation_rules
                FROM secrets
                WHERE secret_name = ? AND deleted_date IS NULL
                """,
                (secret_name,),
            )
            secret = cursor.fetchone()

            if not secret:
                raise ResourceNotFoundException(f"Secret '{secret_name}' not found.")

            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}"
            result = {"ARN": arn, "Name": secret_name}

            if "rotation_lambda_arn" in secret and secret["rotation_lambda_arn"]:
                result["RotationLambdaARN"] = secret["rotation_lambda_arn"]
            if "rotation_rules" in secret and secret["rotation_rules"]:
                result["RotationRules"] = json.loads(secret["rotation_rules"])

            return result

    def rotate_secret(
        self, secret_name: str, client_request_token: Optional[str] = None
    ) -> Dict:
        """Rotate a secret immediately"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if secret exists and get rotation configuration
            cursor.execute(
                """
                SELECT rotation_enabled, rotation_lambda_arn, rotation_rules
                FROM secrets
                WHERE secret_name = ? AND deleted_date IS NULL
                """,
                (secret_name,),
            )
            secret = cursor.fetchone()

            if not secret:
                raise ResourceNotFoundException(f"Secret '{secret_name}' not found.")

            # Check if rotation is configured before proceeding
            rotation_enabled = (
                bool(secret["rotation_enabled"])
                if "rotation_enabled" in secret.keys()
                else False
            )
            rotation_lambda_arn = (
                secret["rotation_lambda_arn"]
                if "rotation_lambda_arn" in secret.keys()
                else None
            )

            if not rotation_enabled or not rotation_lambda_arn:
                raise InvalidRequestException(
                    f"Secret '{secret_name}' is not configured for rotation. "
                    "Use rotate-secret with RotationLambdaARN and RotationRules to configure rotation first."
                )

            # Get current secret value
            cursor.execute(
                """
                SELECT secret_string FROM secret_versions
                WHERE secret_name = ? AND version_stages LIKE ?
                """,
                (secret_name, '%"AWSCURRENT"%'),
            )
            current_version = cursor.fetchone()

            if not current_version:
                raise InvalidRequestException(
                    f"No current version found for secret '{secret_name}'."
                )

            # Decode current value
            current_value = self._decode_secret(current_version["secret_string"])

            # Invoke Lambda rotation function
            try:
                client_request_token = self._invoke_rotation_lambda(
                    rotation_lambda_arn, secret_name, current_value
                )
            except Exception as e:
                logger.error(
                    f"Failed to invoke rotation Lambda for secret '{secret_name}': {e}"
                )
                raise InvalidRequestException(f"Rotation failed: {str(e)}")

            # Get the AWSPENDING version created by the Lambda
            cursor.execute(
                """
                SELECT secret_string FROM secret_versions
                WHERE secret_name = ? AND version_id = ?
                """,
                (secret_name, client_request_token),
            )
            pending_version = cursor.fetchone()

            if not pending_version:
                raise InvalidRequestException(
                    f"Rotation Lambda did not create AWSPENDING version with token '{client_request_token}'."
                )

            new_value = self._decode_secret(pending_version["secret_string"])

            # Create new version
            now = int(time.time())
            version_id = str(uuid.uuid4())

            # Move AWSCURRENT to AWSPREVIOUS
            cursor.execute(
                """
                UPDATE secret_versions
                SET version_stages = ?
                WHERE secret_name = ? AND version_stages LIKE ?
                """,
                (json.dumps(["AWSPREVIOUS"]), secret_name, '%"AWSCURRENT"%'),
            )

            # Move AWSPENDING to AWSCURRENT
            cursor.execute(
                """
                UPDATE secret_versions
                SET version_stages = ?
                WHERE secret_name = ? AND version_id = ?
                """,
                (json.dumps(["AWSCURRENT"]), secret_name, client_request_token),
            )

            # Update rotation metadata
            cursor.execute(
                """
                UPDATE secrets SET
                    last_rotated_date = ?,
                    last_updated_date = ?
                WHERE secret_name = ?
                """,
                (now, now, secret_name),
            )

            conn.commit()

            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}-{client_request_token[:6]}"
            return {
                "ARN": arn,
                "Name": secret_name,
                "VersionId": client_request_token,
            }

    def _invoke_rotation_lambda(
        self, lambda_arn: str, secret_name: str, current_value: str
    ) -> str:
        """Invoke the rotation Lambda function and return the new secret value"""
        # Extract function name from ARN
        # ARN format: arn:aws:lambda:region:account:function:function-name
        try:
            arn_parts = lambda_arn.split(":")
            if len(arn_parts) >= 6 and arn_parts[2] == "lambda": # lame, yeah I know
                function_name = arn_parts[5]
            else:
                raise ValueError(f"Invalid Lambda ARN format: {lambda_arn}")
        except (IndexError, ValueError) as e:
            raise InvalidRequestException(f"Invalid rotation Lambda ARN: {lambda_arn}")

        # Generate a client request token for this rotation
        client_request_token = str(uuid.uuid4())

        # Prepare the payload for the Lambda function following AWS rotation event format
        payload = {
            "SecretId": secret_name,
            "ClientRequestToken": client_request_token,
            "Step": "createSecret",
        }

        # Prepare the request
        lambda_service_url = "http://api:4566"
        url = f"{lambda_service_url}/2015-03-31/functions/{function_name}/invocations"
        data = json.dumps(payload).encode("utf-8")

        # Create request
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(data)),
            },
            method="POST",
        )

        try:
            # Make the HTTP request
            with urllib.request.urlopen(req, timeout=30) as response:
                response_data = response.read().decode("utf-8")
                # The Lambda function doesn't return the secret value directly
                # It creates an AWSPENDING version, so we return the token to identify it.. what a pain
                return client_request_token
        except urllib.error.HTTPError as e:
            error_msg = f"Lambda invocation failed with HTTP {e.code}: {e.read().decode('utf-8')}"
            logger.error(error_msg)
            raise InvalidRequestException(
                f"Rotation Lambda invocation failed: {error_msg}"
            )
        except urllib.error.URLError as e:
            error_msg = f"Failed to connect to Lambda service: {str(e)}"
            logger.error(error_msg)
            raise InvalidRequestException(
                f"Rotation Lambda invocation failed: {error_msg}"
            )
        except Exception as e:
            error_msg = f"Unexpected error during Lambda invocation: {str(e)}"
            logger.error(error_msg)
            raise InvalidRequestException(
                f"Rotation Lambda invocation failed: {error_msg}"
            )


class SecretsManager:
    """Container for Secrets Manager operations"""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize Secrets Manager container"""
        if not hasattr(self, "_initialized"):
            self.db = SecretsManagerDatabase()
            logger.info("SecretsManagerContainer initialized")
            self._initialized = True

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

    def put_resource_policy(self, params: Dict) -> Dict:
        """Put resource policy"""
        secret_id = params.get("SecretId")
        if not secret_id:
            raise InvalidParameterException("SecretId is required")

        resource_policy = params.get("ResourcePolicy")
        if not resource_policy:
            raise InvalidParameterException("ResourcePolicy is required")

        return self.db.put_resource_policy(
            secret_name=secret_id, resource_policy=resource_policy
        )

    def get_resource_policy(self, params: Dict) -> Dict:
        """Get resource policy"""
        secret_id = params.get("SecretId")
        if not secret_id:
            raise InvalidParameterException("SecretId is required")

        return self.db.get_resource_policy(secret_name=secret_id)

    def delete_resource_policy(self, params: Dict) -> Dict:
        """Delete resource policy"""
        secret_id = params.get("SecretId")
        if not secret_id:
            raise InvalidParameterException("SecretId is required")

        return self.db.delete_resource_policy(secret_name=secret_id)

    def rotate_secret(self, params: Dict) -> Dict:
        """Rotate secret"""
        secret_id = params.get("SecretId")
        if not secret_id:
            raise InvalidParameterException("SecretId is required")

        # Check if rotation configuration parameters are provided
        rotation_lambda_arn = params.get("RotationLambdaARN")
        rotation_rules = params.get("RotationRules")

        # If rotation configuration is provided, configure it first
        if rotation_lambda_arn or rotation_rules:
            if not rotation_lambda_arn:
                raise InvalidParameterException(
                    "RotationLambdaARN is required when configuring rotation"
                )
            if not rotation_rules:
                rotation_rules = {}
            self.db.configure_rotation(
                secret_name=secret_id,
                rotation_lambda_arn=rotation_lambda_arn,
                rotation_rules=rotation_rules,
            )

        return self.db.rotate_secret(
            secret_name=secret_id, client_request_token=params.get("ClientRequestToken")
        )

    def cancel_rotate_secret(self, params: Dict) -> Dict:
        """Cancel rotation for a secret"""
        secret_id = params.get("SecretId")
        if not secret_id:
            raise InvalidParameterException("SecretId is required")

        return self.db.cancel_rotate_secret(secret_name=secret_id)

    def get_rotation_policy(self, params: Dict) -> Dict:
        """Get rotation policy"""
        secret_id = params.get("SecretId")
        if not secret_id:
            raise InvalidParameterException("SecretId is required")

        return self.db.get_rotation_policy(secret_name=secret_id)


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
        sm = SecretsManager()
        # Route to appropriate handler
        if operation == "CreateSecret":
            result = sm.create_secret(params)
            return jsonify(result), 200

        elif operation == "GetSecretValue":
            result = sm.get_secret_value(params)
            return jsonify(result), 200

        elif operation == "UpdateSecret":
            result = sm.update_secret(params)
            return jsonify(result), 200

        elif operation == "UpdateSecretVersionStage":
            result = sm.update_secret_version_stage(params)
            return jsonify(result), 200

        elif operation == "DeleteSecret":
            result = sm.delete_secret(params)
            return jsonify(result), 200

        elif operation == "RestoreSecret":
            result = sm.restore_secret(params)
            return jsonify(result), 200

        elif operation == "ListSecrets":
            result = sm.list_secrets(params)
            return jsonify(result), 200

        elif operation == "DescribeSecret":
            result = sm.describe_secret(params)
            return jsonify(result), 200

        elif operation == "ListSecretVersionIds":
            result = sm.list_secret_version_ids(params)
            return jsonify(result), 200

        elif operation == "PutSecretValue":
            result = sm.put_secret_value(params)
            return jsonify(result), 200

        elif operation == "PutResourcePolicy":
            result = sm.put_resource_policy(params)
            return jsonify(result), 200

        elif operation == "GetResourcePolicy":
            result = sm.get_resource_policy(params)
            return jsonify(result), 200

        elif operation == "DeleteResourcePolicy":
            result = sm.delete_resource_policy(params)
            return jsonify(result), 200

        elif operation == "CancelRotateSecret":
            result = sm.cancel_rotate_secret(params)
            return jsonify(result), 200

        elif operation == "RotateSecret":
            result = sm.rotate_secret(params)
            return jsonify(result), 200

        elif operation == "GetRotationPolicy":
            result = sm.get_rotation_policy(params)
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
    secrets_manager = SecretsManager()
    app.run(host="0.0.0.0", port=4566, debug=False)
