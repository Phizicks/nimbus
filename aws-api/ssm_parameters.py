"""
SSM Parameter Store Implementation for LocalCloud
Supports parameters, versions, tags, and secure strings
"""
from typing import Optional, List, Dict, Any
from database import Database
import base64
import logging
import re
import sqlite3
from datetime import datetime, timezone
import json
import os

logger = logging.getLogger(__name__)

DB_PATH = os.getenv('STORAGE_PATH', '/data') + '/ssm_metadata.db'

class SsmDatabase:
    def init_db(self):
        """Initialize SQLite database with tables"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # SSM Parameters table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ssm_parameters (
                account_id TEXT NOT NULL,
                region TEXT NOT NULL,
                parameter_name TEXT NOT NULL,
                parameter_type TEXT NOT NULL,  -- String, StringList, SecureString
                data_type TEXT DEFAULT 'text',
                description TEXT,
                allowed_pattern TEXT,
                tier TEXT DEFAULT 'Standard',  -- Standard, Advanced, Intelligent-Tiering
                last_modified_date TEXT NOT NULL,
                last_modified_user TEXT,
                PRIMARY KEY (account_id, region, parameter_name)
            )
        ''')

        # SSM Parameter Versions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ssm_parameter_versions (
                account_id TEXT NOT NULL,
                region TEXT NOT NULL,
                parameter_name TEXT NOT NULL,
                version INTEGER NOT NULL,
                value TEXT NOT NULL,
                is_encrypted INTEGER DEFAULT 0,  -- 0 or 1
                kms_key_id TEXT,
                created_date TEXT NOT NULL,
                labels TEXT,  -- JSON array of labels
                PRIMARY KEY (account_id, region, parameter_name, version),
                FOREIGN KEY (account_id, region, parameter_name)
                    REFERENCES ssm_parameters(account_id, region, parameter_name)
                    ON DELETE CASCADE
            )
        ''')

        # SSM Parameter Tags table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ssm_parameter_tags (
                account_id TEXT NOT NULL,
                region TEXT NOT NULL,
                parameter_name TEXT NOT NULL,
                tag_key TEXT NOT NULL,
                tag_value TEXT,
                PRIMARY KEY (account_id, region, parameter_name, tag_key),
                FOREIGN KEY (account_id, region, parameter_name)
                    REFERENCES ssm_parameters(account_id, region, parameter_name)
                    ON DELETE CASCADE
            )
        ''')

        # Create indexes for common queries
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ssm_params_name
            ON ssm_parameters(account_id, region, parameter_name)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ssm_params_hierarchy
            ON ssm_parameters(account_id, region, parameter_name)
        ''')

        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")


class SSMParameterStore:
    """SSM Parameter Store implementation"""

    def __init__(self, account_id: str, region: str):
        self.db = SsmDatabase()
        self.db.init_db()

        self.account_id = account_id
        self.region = region

    def _validate_parameter_name(self, name: str) -> bool:
        """Validate parameter name according to AWS rules"""
        if not name or len(name) > 2048:
            return False
        if not name.startswith('/'):
            return False
        # Check for valid characters
        pattern = r'^[a-zA-Z0-9/_.\-]+$'
        return bool(re.match(pattern, name))

    def _validate_allowed_pattern(self, value: str, pattern: str) -> bool:
        """Validate parameter value against allowed pattern"""
        logger.critical(f"Validating value '{value}' against pattern '{pattern}'")
        return bool(re.match(pattern, value))

    def _encrypt_value(self, value: str, kms_key_id: Optional[str] = None) -> Dict[str, Any]:
        """Pseudo-encryption for SecureString parameters"""
        return {
            'encrypted': True,
            'kms_key_id': kms_key_id or 'alias/aws/ssm',
            'value': base64.b64encode(value.encode()).decode()
        }

    def _decrypt_value(self, stored_data: Dict[str, Any]) -> str:
        """Pseudo-decryption for SecureString parameters"""
        if stored_data.get('encrypted'):
            return base64.b64decode(stored_data['value']).decode()
        return stored_data.get('value', '')

    def put_parameter(
        self,
        name: str,
        value: str,
        parameter_type: str = 'String',
        description: str = '',
        kms_key_id: Optional[str] = None,
        overwrite: bool = False,
        allowed_pattern: Optional[str] = None,
        tags: Optional[List[Dict[str, str]]] = None,
        tier: str = 'Standard',
        data_type: str = 'text'
    ) -> Dict[str, Any]:
        """
        Create or update a parameter

        Returns: { 'Version': int, 'Tier': str }
        """
        if not self._validate_parameter_name(name):
            raise ValueError(f"Invalid parameter name: {name}")

        if parameter_type not in ['String', 'StringList', 'SecureString']:
            raise ValueError(f"Invalid parameter type: {parameter_type}")

        # Handle tier and size limits
        if len(value) > 4096 and tier == 'Standard':
            logger.error(f"Putting parameter '{name}' of tier '{tier}' failed due to size limit. size: {len(value)}")
            raise ValueError("Parameter value exceeds maximum length of 4096 characters")
        if len(value) > 8192 and tier == 'Advanced':
            logger.error(f"Putting parameter '{name}' of tier '{tier}' failed due to size limit. size: {len(value)}")
            raise ValueError("Parameter value exceeds maximum length of 8192 characters")

        if allowed_pattern and not self._validate_allowed_pattern(value, allowed_pattern):
            logger.error(f"Putting parameter '{name}' of type '{parameter_type}' with allowed_pattern '{allowed_pattern}' failed validation.")
            raise ValueError("Parameter value does not match allowed pattern")

        current = {}
        try:
            current = self.get_parameter(name, with_decryption=True)
        except ValueError:
            # Parameter does not exist yet, which is fine
            pass

        if current and current.get('Parameter',{}).get('Type',"") != parameter_type:
            logger.error(f"Putting parameter '{name}' failed due to type mismatch. existing: {current.get('Parameter',{}).get('Type','')}, new: {parameter_type}")
            raise ValueError("Parameter type mismatch with existing parameter")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        try:
            # Check if parameter exists
            cursor.execute('''
                SELECT parameter_name FROM ssm_parameters
                WHERE account_id = ? AND region = ? AND parameter_name = ?
            ''', (self.account_id, self.region, name))

            exists = cursor.fetchone() is not None

            if exists and not overwrite:
                conn.close()
                raise ValueError(f"Parameter {name} already exists. Use overwrite=true to update.")

            now = datetime.now(timezone.utc).isoformat()

            # Insert or update parameter metadata
            cursor.execute('''
                INSERT OR REPLACE INTO ssm_parameters (
                    account_id, region, parameter_name, parameter_type,
                    data_type, description, allowed_pattern, tier,
                    last_modified_date, last_modified_user
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.account_id, self.region, name, parameter_type,
                data_type, description, allowed_pattern, tier,
                now, 'localcloud-user'
            ))

            # Get next version number
            cursor.execute('''
                SELECT COALESCE(MAX(version), 0) + 1
                FROM ssm_parameter_versions
                WHERE account_id = ? AND region = ? AND parameter_name = ?
            ''', (self.account_id, self.region, name))

            version = cursor.fetchone()[0]

            # Handle encryption for SecureString
            stored_value = value
            is_encrypted = 0
            if parameter_type == 'SecureString':
                encrypted_data = self._encrypt_value(value, kms_key_id)
                stored_value = encrypted_data['value']
                is_encrypted = 1
                kms_key_id = encrypted_data['kms_key_id']

            # Insert new version
            cursor.execute('''
                INSERT INTO ssm_parameter_versions (
                    account_id, region, parameter_name, version,
                    value, is_encrypted, kms_key_id, created_date, labels
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.account_id, self.region, name, version,
                stored_value, is_encrypted, kms_key_id, now, json.dumps([])
            ))

            # Add tags if provided
            if tags:
                for tag in tags:
                    cursor.execute('''
                        INSERT OR REPLACE INTO ssm_parameter_tags (
                            account_id, region, parameter_name, tag_key, tag_value
                        ) VALUES (?, ?, ?, ?, ?)
                    ''', (
                        self.account_id, self.region, name,
                        tag['Key'], tag['Value']
                    ))

            conn.commit()

            return {
                'Version': version,
                'Tier': tier
            }

        finally:
            conn.close()

    def get_parameter(
        self,
        name: str,
        with_decryption: bool = False,
        version: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Get a parameter by name

        Returns parameter metadata and value
        """
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        try:
            # Get parameter metadata
            cursor.execute('''
                SELECT parameter_type, data_type, description,
                       last_modified_date, tier
                FROM ssm_parameters
                WHERE account_id = ? AND region = ? AND parameter_name = ?
            ''', (self.account_id, self.region, name))

            param_row = cursor.fetchone()
            if not param_row:
                raise ValueError(f"Parameter {name} not found")

            parameter_type, data_type, description, last_modified, tier = param_row

            # Get version data
            if version:
                cursor.execute('''
                    SELECT version, value, is_encrypted, kms_key_id, created_date
                    FROM ssm_parameter_versions
                    WHERE account_id = ? AND region = ?
                      AND parameter_name = ? AND version = ?
                ''', (self.account_id, self.region, name, version))
            else:
                cursor.execute('''
                    SELECT version, value, is_encrypted, kms_key_id, created_date
                    FROM ssm_parameter_versions
                    WHERE account_id = ? AND region = ? AND parameter_name = ?
                    ORDER BY version DESC LIMIT 1
                ''', (self.account_id, self.region, name))

            version_row = cursor.fetchone()
            if not version_row:
                raise ValueError(f"No version found for parameter {name}")

            ver, stored_value, is_encrypted, kms_key_id, created = version_row

            # Decrypt if needed
            value = stored_value
            if is_encrypted and with_decryption:
                value = self._decrypt_value({
                    'encrypted': True,
                    'value': stored_value
                })
            elif is_encrypted and not with_decryption:
                # Return encrypted value as-is if decryption not requested
                value = stored_value

            arn = f"arn:aws:ssm:{self.region}:{self.account_id}:parameter{name}"

            return {
                'Parameter': {
                    'Name': name,
                    'Type': parameter_type,
                    'Value': value,
                    'Version': ver,
                    'LastModifiedDate': datetime.fromisoformat(last_modified.replace("Z", "+00:00")).timestamp(),
                    'ARN': arn,
                    'DataType': data_type
                }
            }

        finally:
            conn.close()

    def get_parameters(
        self,
        names: List[str],
        with_decryption: bool = False
    ) -> Dict[str, Any]:
        """Get multiple parameters by name"""
        parameters = []
        invalid_parameters = []

        for name in names:
            try:
                result = self.get_parameter(name, with_decryption)
                parameters.append(result['Parameter'])
            except ValueError:
                invalid_parameters.append(name)

        return {
            'Parameters': parameters,
            'InvalidParameters': invalid_parameters
        }

    def get_parameters_by_path(
        self,
        path: str,
        recursive: bool = False,
        with_decryption: bool = False,
        max_results: int = 10,
        next_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get parameters by hierarchical path

        Example: path='/prod/app/' returns all parameters under that path
        """
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        try:
            # Build query based on recursive flag
            if recursive:
                # Match path and all subpaths
                pattern = f"{path}%"
            else:
                # Match only immediate children (one level deep)
                # e.g., /prod/app/ matches /prod/app/key but not /prod/app/sub/key
                pattern = f"{path}%"

            cursor.execute('''
                SELECT p.parameter_name, p.parameter_type, p.data_type,
                       p.last_modified_date, v.version, v.value,
                       v.is_encrypted, v.kms_key_id
                FROM ssm_parameters p
                JOIN ssm_parameter_versions v ON
                    p.account_id = v.account_id AND
                    p.region = v.region AND
                    p.parameter_name = v.parameter_name
                WHERE p.account_id = ? AND p.region = ?
                  AND p.parameter_name LIKE ?
                  AND v.version = (
                      SELECT MAX(version)
                      FROM ssm_parameter_versions
                      WHERE account_id = p.account_id
                        AND region = p.region
                        AND parameter_name = p.parameter_name
                  )
                ORDER BY p.parameter_name
                LIMIT ?
            ''', (self.account_id, self.region, pattern, max_results))

            rows = cursor.fetchall()

            parameters = []
            for row in rows:
                name, param_type, data_type, last_modified, version, value, is_encrypted, kms_key_id = row

                # Filter out if not recursive and more than one level deep
                if not recursive:
                    # Count slashes after the base path
                    relative_path = name[len(path):]
                    if '/' in relative_path:
                        continue

                # Decrypt if needed
                if is_encrypted and with_decryption:
                    value = self._decrypt_value({'encrypted': True, 'value': value})

                arn = f"arn:aws:ssm:{self.region}:{self.account_id}:parameter{name}"

                parameters.append({
                    'Name': name,
                    'Type': param_type,
                    'Value': value,
                    'Version': version,
                    'LastModifiedDate': datetime.fromisoformat(last_modified.replace("Z", "+00:00")).timestamp(),
                    'ARN': arn,
                    'DataType': data_type
                })

            return {
                'Parameters': parameters,
                'NextToken': None  # Pagination not implemented yet
            }

        finally:
            conn.close()

    def delete_parameter(self, name: str) -> Dict[str, Any]:
        """Delete a parameter and all its versions"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        try:
            # Check if exists
            cursor.execute('''
                SELECT parameter_name FROM ssm_parameters
                WHERE account_id = ? AND region = ? AND parameter_name = ?
            ''', (self.account_id, self.region, name))

            if not cursor.fetchone():
                raise ValueError(f"Parameter {name} not found")

            # Delete parameter (CASCADE will delete versions and tags)
            cursor.execute('''
                DELETE FROM ssm_parameters
                WHERE account_id = ? AND region = ? AND parameter_name = ?
            ''', (self.account_id, self.region, name))
            conn.commit()
            cursor.execute('''
                DELETE FROM ssm_parameter_versions
                WHERE account_id = ? AND region = ? AND parameter_name = ?
            ''', (self.account_id, self.region, name))
            conn.commit()
            cursor.execute('''
                DELETE FROM ssm_parameter_tags
                WHERE account_id = ? AND region = ? AND parameter_name = ?
            ''', (self.account_id, self.region, name))
            conn.commit()

            return {}

        finally:
            conn.close()

    def describe_parameters(
        self,
        filters: Optional[List[Dict[str, Any]]] = None,
        max_results: int = 50,
        next_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        List parameters with optional filters

        Filters: [{'Key': 'Name', 'Values': ['pattern']}]
        """
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        try:
            query = '''
                SELECT p.parameter_name, p.parameter_type, p.data_type,
                       p.description, p.last_modified_date, p.tier,
                       MAX(v.version) as version
                FROM ssm_parameters p
                LEFT JOIN ssm_parameter_versions v ON
                    p.account_id = v.account_id AND
                    p.region = v.region AND
                    p.parameter_name = v.parameter_name
                WHERE p.account_id = ? AND p.region = ?
            '''

            params = [self.account_id, self.region]

            # Apply filters (simplified - only Name filter for now)
            if filters:
                for f in filters:
                    if f.get('Key') == 'Name':
                        query += ' AND p.parameter_name LIKE ?'
                        params.append(f['Values'][0])

            query += ' GROUP BY p.parameter_name ORDER BY p.parameter_name LIMIT ?'
            params.append(max_results)

            cursor.execute(query, params)
            rows = cursor.fetchall()

            parameters = []
            for row in rows:
                name, param_type, data_type, desc, last_modified, tier, version = row
                parameters.append({
                    'Name': name,
                    'Type': param_type,
                    'DataType': data_type,
                    'Description': desc or '',
                    'LastModifiedDate': datetime.fromisoformat(last_modified.replace("Z", "+00:00")).timestamp(),
                    'Tier': tier,
                    'Version': version or 1
                })

            return {
                'Parameters': parameters,
                'NextToken': None
            }

        finally:
            conn.close()

    def get_parameter_history(self, name: str, with_decryption: bool = False, max_results: int = 50) -> Dict[str, Any]:
        """Get version history for a parameter"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT p.parameter_type, v.version, v.value, v.is_encrypted, v.created_date, v.labels
                FROM ssm_parameters p
                JOIN ssm_parameter_versions v ON
                    p.account_id = v.account_id AND
                    p.region = v.region AND
                    p.parameter_name = v.parameter_name
                WHERE p.account_id = ? AND p.region = ? AND p.parameter_name = ?
                ORDER BY v.version DESC
                LIMIT ?
            ''', (self.account_id, self.region, name, max_results))

            rows = cursor.fetchall()

            if not rows:
                raise ValueError(f"Parameter {name} not found")

            parameters = []
            for row in rows:
                param_type, version, value, is_encrypted, created, labels = row

                if is_encrypted and with_decryption:
                    value = self._decrypt_value({'encrypted': True, 'value': value})

                parameters.append({
                    'Name': name,
                    'Type': param_type,
                    'Version': version,
                    'LastModifiedDate': datetime.fromisoformat(created.replace("Z", "+00:00")).timestamp(),
                    'Value': value,
                    'Labels': json.loads(labels) if labels else []
                })

            return {
                'Parameters': parameters,
                'NextToken': None
            }

        finally:
            conn.close()

    def get_parameter_tags(self, parameter_name):
        """
        Retrieve tags for a given SSM parameter from SQLite.
        Returns a list of dicts like [{'Key': ..., 'Value': ...}, ...]
        """
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        logger.critical(f"parameter_name: {parameter_name}")

        cursor.execute('''
            SELECT tag_key, tag_value
            FROM ssm_parameter_tags
            WHERE account_id = ? AND region = ? AND parameter_name = ?
        ''', (self.account_id, self.region, parameter_name))
        tags = [{"Key": row[0], "Value": row[1]} for row in cursor.fetchall()]

        conn.close()
        return { "TagList": tags }

