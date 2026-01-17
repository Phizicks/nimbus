import sqlite3
import logging
from datetime import datetime, timezone
import os
import json

# Database path for storing metadata about functions and their states.
DB_PATH = os.getenv("STORAGE_PATH", '/data') + '/aws_metadata.db'

logger = logging.getLogger(__name__)

class Database:
    def init_db(self):
        """Initialize SQLite database with tables"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # ECR repositories table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS repositories (
                repository_name TEXT PRIMARY KEY,
                repository_uri TEXT,
                registry_id TEXT,
                created_at TEXT
            )
        ''')

        # ECR images table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS images (
                repository_name TEXT,
                image_tag TEXT,
                image_digest TEXT,
                image_size INTEGER,
                pushed_at TEXT,
                docker_image_id TEXT,
                PRIMARY KEY (repository_name, image_tag),
                FOREIGN KEY (repository_name) REFERENCES repositories(repository_name)
            )
        ''')

        # Lambda functions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS lambda_functions (
                function_name TEXT PRIMARY KEY,
                function_arn TEXT NOT NULL,
                runtime TEXT,
                handler TEXT,
                role TEXT NOT NULL,
                code_size INTEGER DEFAULT 0,
                state TEXT DEFAULT 'Active',
                last_update_status TEXT DEFAULT 'Successful',
                package_type TEXT NOT NULL,
                image_uri TEXT,
                code_sha256 TEXT,
                endpoint TEXT,
                container_name TEXT,
                host_port INTEGER,
                environment TEXT,
                created_at TEXT NOT NULL,
                last_modified TEXT NOT NULL,
                provisioned_concurrency INTEGER DEFAULT 0,
                reserved_concurrency INTEGER DEFAULT 100,
                logging_config TEXT
            )
        ''')

        # Lambda function container mapping table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS container_mappings (
                function_name TEXT PRIMARY KEY,
                container_id TEXT NOT NULL,
                container_ip TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')

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

    def get_function_from_db(self, function_name):
        """Retrieve a function from the database"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM lambda_functions WHERE function_name = ?', (function_name,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        # Deserialize environment JSON
        environment = {}
        if row[14]:  # environment column
            try:
                environment = json.loads(row[14])
            except (json.JSONDecodeError, TypeError):
                logger.warning(f"Failed to parse environment for {function_name}")
                environment = {}

        # Deserialize logging_config JSON (new column at index 19)
        logging_config = None
        if len(row) > 19 and row[19]:  # logging_config column
            try:
                logging_config = json.loads(row[19])
            except (json.JSONDecodeError, TypeError):
                logger.warning(f"Failed to parse logging_config for {function_name}")
                logging_config = None

        result = {
            'FunctionName': row[0],
            'FunctionArn': row[1],
            'Runtime': row[2],
            'Handler': row[3],
            'Role': row[4],
            'CodeSize': row[5],
            'State': row[6],
            'LastUpdateStatus': row[7],
            'PackageType': row[8],
            'ImageUri': row[9],
            'CodeSha256': row[10],
            'Endpoint': row[11],
            'ContainerName': row[12],
            'HostPort': row[13],
            'Environment': environment,
            'CreatedAt': row[15],
            'LastModified': row[16]
        }

        # Add LoggingConfig if it exists
        if logging_config:
            result['LoggingConfig'] = logging_config

        return result

    def save_function_to_db(self, function_config):
        """Save or update a function in the database"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        now = datetime.now(timezone.utc).isoformat()

        # Serialize environment variables to JSON
        environment = function_config.get('Environment', {})
        environment_json = json.dumps(environment) if environment else '{}'

        # Serialize logging config to JSON
        logging_config = function_config.get('LoggingConfig')
        logging_config_json = json.dumps(logging_config) if logging_config else None

        cursor.execute('''
            INSERT OR REPLACE INTO lambda_functions (
                function_name,
                function_arn,
                runtime,
                handler,
                role,
                code_size,
                state,
                last_update_status,
                package_type,
                image_uri,
                code_sha256,
                endpoint,
                container_name,
                host_port,
                environment,
                created_at,
                last_modified,
                provisioned_concurrency,
                reserved_concurrency,
                logging_config
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?,  -- host_port
                ?,  -- environment
                COALESCE((SELECT created_at FROM lambda_functions WHERE function_name = ?), ?),
                ?,  -- last_modified
                ?,  -- provisioned_concurrency
                ?,  -- reserved_concurrency
                ?   -- logging_config
            )
        ''', (
            function_config.get('FunctionName', ''),
            function_config.get('FunctionArn', ''),
            function_config.get('Runtime', ''),
            function_config.get('Handler', ''),
            function_config.get('Role', ''),
            function_config.get('CodeSize', 0),
            function_config.get('State', 'Active'),
            function_config.get('LastUpdateStatus', 'Successful'),
            function_config.get('PackageType', ''),
            function_config.get('ImageUri', ''),
            function_config.get('CodeSha256', ''),
            function_config.get('Endpoint', ''),
            function_config.get('ContainerName', ''),
            function_config.get('HostPort', 0),
            environment_json,
            function_config.get('FunctionName', ''),  # for COALESCE subquery
            now,                                      # COALESCE fallback value
            now,                                      # last_modified
            function_config.get('ProvisionedConcurrency', 0),
            function_config.get('ReservedConcurrency', 0),
            logging_config_json
        ))

        conn.commit()
        conn.close()

    def delete_function_from_db(self, function_name):
        """Delete a function from the database"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM lambda_functions WHERE function_name = ?', (function_name,))
        conn.commit()
        conn.close()

    def list_functions_from_db(self):
        """List all functions from the database"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM lambda_functions')
        rows = cursor.fetchall()
        conn.close()

        functions = []
        for row in rows:
            # Deserialize environment JSON
            environment = {}
            if row[14]:  # environment column
                try:
                    environment = json.loads(row[14])
                except (json.JSONDecodeError, TypeError):
                    logger.warning(f"Failed to parse environment for {row[0]}")
                    environment = {}

            # Deserialize logging_config JSON
            logging_config = None
            if len(row) > 19 and row[19]:  # logging_config column
                try:
                    logging_config = json.loads(row[19])
                except (json.JSONDecodeError, TypeError):
                    logger.warning(f"Failed to parse logging_config for {row[0]}")
                    logging_config = None

            function_data = {
                'FunctionName': row[0],
                'FunctionArn': row[1],
                'Runtime': row[2],
                'Handler': row[3],
                'Role': row[4],
                'CodeSize': row[5],
                'State': row[6],
                'LastUpdateStatus': row[7],
                'PackageType': row[8],
                'ImageUri': row[9],
                'CodeSha256': row[10],
                'Environment': environment,
                'LastModified': row[16]
            }

            # Add LoggingConfig if it exists
            if logging_config:
                function_data['LoggingConfig'] = logging_config

            functions.append(function_data)

        return functions
