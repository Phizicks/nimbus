from queue import Queue, Empty
import zipfile
from log_manager import LogManager
from dataclasses import dataclass, field
import threading
from collections import defaultdict
from typing import Dict, Optional
from pathlib import Path
from hashlib import sha256
import copy
import logging
import time
import uuid
import os
import sys
import json
import docker
import base64
import sqlite3
import requests
from datetime import datetime, timezone
from timedlocking import TimedLock
from flask import Flask, request, jsonify, Response
import custom_logger
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)

# AWS API endpoint for centralizing logs
AWS_API_ENDPOINT = os.getenv('AWS_API_ENDPOINT', 'http://api:4566')

class C:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


# Configuration
ACCOUNT_ID = "456645664566"
REGISTRY_HOST = os.getenv('REGISTRY_HOST', "ecr:5000")
REGION="ap-southeast-2" # TODO config or parsed
LOCALCLOUD_API_HOSTNAME = os.getenv("LOCALCLOUD_API_HOSTNAME", 'host.docker.internal')
LOCALCLOUD_NETWORK_NAME = os.getenv("LOCALCLOUD_NETWORK_NAME", 'localcloud')
STORAGE_PATH = os.getenv("STORAGE_PATH", './data')
DB_PATH = os.getenv('STORAGE_PATH', '/data') + '/lambda_metadata.db'

# Storage for function code
FUNCTIONS_DIR = Path(f'{STORAGE_PATH}/lambda-functions')
FUNCTIONS_DIR.mkdir(exist_ok=True)

# Runtime configurations - TODO make config
RUNTIME_BASE_IMAGES = {
    'python3.10': 'public.ecr.aws/lambda/python:3.10',
    'python3.11': 'public.ecr.aws/lambda/python:3.11',
    'python3.12': 'public.ecr.aws/lambda/python:3.12',
    'python3.13': 'public.ecr.aws/lambda/python:3.13',
    'python3.14': 'public.ecr.aws/lambda/python:3.14',
    'nodejs20.x': 'public.ecr.aws/lambda/nodejs:20',
    'nodejs24.x': 'public.ecr.aws/lambda/nodejs:24',
    'nodejs22.x': 'public.ecr.aws/lambda/nodejs:22',
    'java8.al2': 'public.ecr.aws/lambda/java:8.al2',
    'java11': 'public.ecr.aws/lambda/java:11',
    'java17': 'public.ecr.aws/lambda/java:17',
    'java20': 'public.ecr.aws/lambda/java:20',
    'java21': 'public.ecr.aws/lambda/java:21',
    'java25': 'public.ecr.aws/lambda/java:25',
    'go1.x': 'public.ecr.aws/lambda/go:1',
    'provided.al2': 'public.ecr.aws/lambda/provided:al2',
    'provided.al2023': 'public.ecr.aws/lambda/provided:al2023',
}


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
                logging_config TEXT,
                image_config TEXT
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
        conn.row_factory = sqlite3.Row  # Enable access by column name
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM lambda_functions WHERE function_name = ?', (function_name,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        # Deserialize environment JSON
        environment = {}
        if row['environment']:
            try:
                environment = json.loads(row['environment'])
            except (json.JSONDecodeError, TypeError):
                logger.warning(f"Failed to parse environment for {function_name}")
                environment = {}

        logging_config = None
        if 'logging_config' in row.keys() and row['logging_config']:
            try:
                logging_config = json.loads(row['logging_config'])
            except (json.JSONDecodeError, TypeError):
                logger.warning(f"Failed to parse logging_config for {function_name}")
                logging_config = None

        result = {
            'FunctionName': row['function_name'],
            'FunctionArn': row['function_arn'],
            'Runtime': row['runtime'],
            'Handler': row['handler'],
            'Role': row['role'],
            'CodeSize': row['code_size'],
            'State': row['state'],
            'LastUpdateStatus': row['last_update_status'],
            'PackageType': row['package_type'],
            'ImageUri': row['image_uri'],
            'CodeSha256': row['code_sha256'],
            'Endpoint': row['endpoint'],
            'ContainerName': row['container_name'],
            'HostPort': row['host_port'],
            'Environment': environment,
            'CreatedAt': row['created_at'],
            'LastModified': row['last_modified'],
            'ProvisionedConcurrency': row['provisioned_concurrency'],
            'ReservedConcurrency': row['reserved_concurrency'],
            'LoggingConfig': row['logging_config'],
        }

        if logging_config:
            result['LoggingConfig'] = logging_config
        if row['image_config']:
            result['ImageConfig'] = row['image_config']

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

        # Serialize image config to JSON (command, entrypoint, workdir)
        image_config = function_config.get('ImageConfig')
        image_config_json = json.dumps(image_config) if image_config else None

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
                logging_config,
                image_config
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?,  -- host_port
                ?,  -- environment
                COALESCE((SELECT created_at FROM lambda_functions WHERE function_name = ?), ?),
                ?,  -- last_modified
                ?,  -- provisioned_concurrency
                ?,  -- reserved_concurrency
                ?,  -- logging_config
                ?   -- image_config
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
            logging_config_json,
            image_config_json
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
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('SELECT * FROM lambda_functions')
            rows = cursor.fetchall()
            conn.close()

            functions = []
            for row in rows:
                environment = {}
                if row['environment']:
                    try:
                        environment = json.loads(row['environment'])
                    except (json.JSONDecodeError, TypeError):
                        logger.warning(f"Failed to parse environment for {row['function_name']}")
                        environment = {}

                logging_config = None
                if 'logging_config' in row.keys() and row['logging_config']:
                    try:
                        logging_config = json.loads(row['logging_config'])
                    except (json.JSONDecodeError, TypeError):
                        logger.warning(f"Failed to parse logging_config for {row['function_name']}")
                        logging_config = None

                function_data = {
                    'FunctionName': row['function_name'],
                    'FunctionArn': row['function_arn'],
                    'Runtime': row['runtime'],
                    'Handler': row['handler'],
                    'Role': row['role'],
                    'CodeSize': row['code_size'],
                    'State': row['state'],
                    'LastUpdateStatus': row['last_update_status'],
                    'PackageType': row['package_type'],
                    'ImageUri': row['image_uri'],
                    'CodeSha256': row['code_sha256'],
                    'Environment': environment,
                    'LastModified': row['last_modified'],
                    'ProvisionedConcurrency': row['provisioned_concurrency'],
                    'ReservedConcurrency': row['reserved_concurrency']
                }

                # Add LoggingConfig if it exists
                if logging_config:
                    function_data['LoggingConfig'] = logging_config

                functions.append(function_data)

            return functions

    def __init__(self):
        self.init_db()

class ContainerState(Enum):
    STARTING =   'starting'      # starting container
    READY =      'ready'         # registered
    LEASED =     'leased'        # polling invocation/next
    RUNNING =    'running'       # handling invocation
    DRAINING =   'draining'      # scaling down, updated lambda, or deleted
    TERMINATED = 'terminated'    # terminating/ed instance

@dataclass
class ContainerMetadata:
    """Track all metadata for a Lambda container"""
    container_id: str
    container_name: str
    function_name: str
    ip_address: Optional[str] = None
    init_start_time: float = field(default_factory=time.time)  # Container creation time
    init_end_time: Optional[float] = None  # When container became ready
    first_invocation: bool = True  # Track if this is first invocation (cold start)
    last_activity: float = field(default_factory=time.time)
    state: ContainerState = ContainerState.STARTING

    def mark_warm(self):
        """Mark container as warm (has handled at least one invocation)"""
        self.first_invocation = False

    def is_cold_start(self) -> bool:
        """Check if next invocation will be a cold start"""
        return self.first_invocation

    def get_init_duration_ms(self) -> Optional[float]:
        """Get initialization duration in milliseconds"""
        if self.init_end_time:
            return (self.init_end_time - self.init_start_time) * 1000
        return None

    def get_state(self) -> ContainerState:
        """Get state of container"""
        return self.state

    def update_last_activity(self, lifecycle_manager=None):
        """Update last_activity timestamp to current time and sync with container_activity"""
        self.last_activity = time.time()
        # Also update container_activity in lifecycle manager if provided
        if lifecycle_manager:
            lifecycle_manager.container_activity[self.container_id] = self.last_activity

# Container lifecycle manager
class ContainerLifecycleManager:
    """Manages Lambda container scaling, startup, and shutdown"""
    _lock = TimedLock(warn_threshold=15)

    def __init__(self, docker_client, check_interval=1):
        with self._lock("ContainerLifecycleManager.__init__"):
            self.docker_client = docker_client
            self.log_manager = LogManager(docker_client)
            self.log_manager.start()
            self.check_interval = check_interval
            self.running = False
            self.thread = None
            self._invocation_responses = {}
            self._invocation_timing = {}
            self._invocation_queues = {}
            # self.invocation = {}
            self.container_function_map = {}

            self.db = Database()
            self.container_metadata = {}


            self.function_configs = defaultdict(lambda: {
                'provisioned': 0,
                'reserved': 100,
                'scale_up_threshold': 2,
                'idle_timeout': 60,
            })

            self.container_activity = {}

            logger.info(f"ContainerLifecycleManager initialized with instance ID: {id(self)}")

    def _refresh_function_configs(self):
        """Refresh function configurations from database to pick up external changes"""
        functions = self.db.list_functions_from_db()

        for func in functions:
            function_name = func['FunctionName']
            provisioned = func.get('ProvisionedConcurrency', 0)
            reserved = func.get('ReservedConcurrency', 100)

            # Update config if values changed
            current_config = self.function_configs[function_name]
            if (current_config['provisioned'] != provisioned or
                current_config['reserved'] != reserved):

                logger.info(f"Config change detected for {function_name}: "
                        f"provisioned {current_config['provisioned']}->{provisioned}, "
                        f"reserved {current_config['reserved']}->{reserved}")

                self.function_configs[function_name]['provisioned'] = provisioned
                self.function_configs[function_name]['reserved'] = reserved

    @property
    def invocation_responses(self):
        return self._invocation_responses

    @invocation_responses.setter
    def invocation_responses(self, value):
        if not isinstance(value, dict):
            raise ValueError("Invocation responses must be a dictionary")
        self._invocation_responses = value

    @property
    def invocation_timing(self):
        return self._invocation_timing

    @invocation_timing.setter
    def invocation_timing(self, value):
        if not isinstance(value, dict):
            raise ValueError("Invocation timing must be a dictionary")
        self._invocation_timing = value

    @property
    def invocation_queues(self) -> Dict[str, Queue]:
        """Read-only access to invocation queues - no lock needed for reads"""
        return self._invocation_queues

    def build_function_image(self, function_name, runtime='python3.11', image_uri=None, function_path=None, handler='lambda_function.handler'):
        """Build the Docker image for a function without starting a container"""
        if image_uri:
            # Image already exists, just verify it's pullable
            try:
                self.docker_client.images.pull(image_uri)
                logger.info(f"Pulled image for {function_name}: {image_uri}")
                return image_uri, None, None
            except Exception as e:
                logger.error(f"Failed to pull image {image_uri}: {e}")
                return None, {'__type': 'InvalidParameterValueException', 'message': f"Failed to pull image: {e}"}, 400
        elif function_path:
            # Build image from code
            dockerfile = function_path / 'Dockerfile'
            dockerfile.write_text(self.create_dockerfile_for_runtime(runtime, handler))
            image_tag = f"lambda-{function_name}:latest"

            try:
                logger.info(f"Building image from {function_path}")
                _, logs = self.docker_client.images.build(path=str(function_path), tag=image_tag, rm=True)
                for log in logs:
                    if 'stream' in log:
                        logger.info(log['stream'].strip())

                logger.info(f"Successfully built image: {image_tag}")
                return image_tag, None, None

            except docker.errors.BuildError as e:
                logger.error(f"Build error: {e}")
                return None, {'__type': 'InvalidParameterValueException', 'message': f"Failed to build image: {e}"}, 400
        else:
            return None, {'__type': 'InvalidParameterValueException', 'message': 'Either ImageUri or function code must be provided'}, 400

    def set_invocation_queue(self, function_name, message) -> int:
        """
        Thread-safe Setter for invocation queues.
        """
        function_queue = self.get_invocation_queue(function_name)
        function_queue.put(message)
        logger.info(f"Message added to queue for {function_name}. New queue size: {function_queue.qsize()}")
        return function_queue.qsize()

    def get_invocation_queue(self, function_name) -> Queue:
        """
        Thread-safe getter for invocation queues.
        Always returns the SAME queue for a given function.
        Lock only needed during queue creation.
        """
        # Fast path - queue already exists (most common case)
        if function_name in self._invocation_queues:
            return self._invocation_queues[function_name]

        # Slow path - need to create queue (lock required)
        with self._lock("ContainerLifecycleManager.get_invocation_queue"):
            # Double-check after acquiring lock
            if function_name not in self._invocation_queues:
                logger.info(f"Creating new invocation queue for {function_name}")
                self._invocation_queues[function_name] = Queue()
                logger.debug(f"Queue created with ID: {id(self._invocation_queues[function_name])}")

            return self._invocation_queues[function_name]

    def get_invocation_queue_task(self, function_name, timeout=5) -> Dict:
        """Get next invocation task for a function, blocking."""
        queue_obj = self.get_invocation_queue(function_name)

        try:
            queue_task = queue_obj.get(timeout=5)
            logger.info(f'Retrieved task from queue for Function:{function_name} Queue:{queue_task}')
            return queue_task
        except Exception as e:
            raise
        except Empty:
            logger.debug(f'No tasks available for {function_name} after {timeout}s timeout')
            # Re-raise so caller can distinguish from other errors
            raise

    def start(self):
        """Start the lifecycle manager thread"""
        if self.running:
            logger.warning("ContainerLifecycleManager already running")
            return

        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("ContainerLifecycleManager started")

    def stop(self, timeout=900):
        """Stop the lifecycle manager and gracefully shutdown containers"""
        logger.info("Stopping ContainerLifecycleManager...")
        self.running = False

        if self.thread:
            self.thread.join(timeout=5)

        # Gracefully shutdown all localcloud containers
        self._graceful_shutdown_all(timeout)
        logger.info("ContainerLifecycleManager stopped")

    def register_container(self, container_id, container_name, function_name, ip_address, state):
        """Register a container in the mapping tables"""
        with self._lock("ContainerLifecycleManager.register_container"):
            self.container_function_map[container_id] = function_name
            # Create metadata entry
            if container_id not in self.container_metadata:
                logger.info(f'Registered new ContainerID:{C.MAGENTA}{container_id}{C.RESET} -> ContainerName:{C.YELLOW}{container_name}{C.RESET} IP:{ip_address}')
                self.container_metadata[container_id] = ContainerMetadata(
                    container_id=container_id,
                    container_name=container_name,
                    function_name=function_name,
                    ip_address=ip_address,
                    init_start_time=time.time(),
                    state=state
                )
        logger.debug(f'DATA self.container_metadata ({self.container_metadata})')

    def update_container_ip(self, container_id, ip_address):
        """Update the IP address for an already-registered container"""
        with self._lock("ContainerLifecycleManager.update_container_ip"):
            if container_id in self.container_metadata:
                old_ip = self.container_metadata[container_id].ip_address
                self.container_metadata[container_id].ip_address = ip_address
                if old_ip != ip_address:
                    logger.debug(f"Updated IP for container {C.MAGENTA}{container_id}{C.RESET}: {old_ip} -> {ip_address}")
            else:
                logger.error(f"Attempted to update IP for unregistered container {C.MAGENTA}{container_id}{C.RESET}")
                raise ValueError(f"Attempted to update IP for unregistered container {container_id}")

    def update_container_state(self, container_id, state: ContainerState):
        """Update the state for an already-registered container"""
        with self._lock("ContainerLifecycleManager.update_container_state"):
            if container_id in self.container_metadata:
                old_state = self.container_metadata[container_id].state
                self.container_metadata[container_id].state = state
                if old_state != state:
                    logger.debug(f"Updated 'state' for container {C.MAGENTA}{container_id}{C.RESET}: {old_state} -> {state}")
            else:
                logger.error(f"Attempted to update 'state' for unregistered container {C.MAGENTA}{container_id}{C.RESET}")
                raise ValueError(f"Attempted to update 'state' for unregistered container {container_id}")

    def unregister_container(self, container_id: str):
        """Completely remove container from tracking."""
        try:
            # Remove from activity tracking
            self.container_activity.pop(container_id, None)

            # Remove metadata
            self.container_metadata.pop(container_id, None)

            # Remove from function map
            self.container_function_map.pop(container_id, None)

            # Optionally remove invocation queue reference if tied to container
            for fname, queue in list(self.invocation_queues.items()):
                if getattr(queue, "container_id", None) == container_id:
                    logger.critical(f'Invocation queue for Function:{fname} ContainerId:{C.MAGENTA}{container_id}{C.RESET} deleted as container is deregistered')
                    del self.invocation_queues[fname]
                    logger.debug(f"Removed invocation queue for {fname} tied to {C.MAGENTA}{container_id}{C.RESET}")

            logger.info(f"Container {C.MAGENTA}{container_id}{C.RESET} fully unregistered")

        except Exception as e:
            logger.error(f"Error unregistering container {C.MAGENTA}{container_id}{C.RESET}: {e}", exc_info=True)

    def mark_container_ready(self, container_id):
        """Mark container as initialized and ready"""
        if container_id in self.container_metadata:
            metadata = self.container_metadata[container_id]
            if metadata.init_end_time is None:
                metadata.init_end_time = time.time()
                init_duration = metadata.get_init_duration_ms()
                logger.info(f"Container {C.MAGENTA}{container_id}{C.RESET} ready - Init Duration: {init_duration:.2f}ms")
        else:
            logger.warning(f"Container {C.MAGENTA}{container_id}{C.RESET} not found in metadata when marking ready")

    def get_container_metadata(self, container_id):
        """Get metadata for a container"""
        return self.container_metadata.get(container_id)

    def get_container_metadata_by_ip(self, container_ip):
        """Get metadata for a container by IP address.

        If direct IP lookup fails, tries to find containers with empty IP in STARTING state
        and updates their IP by querying Docker.
        """

        with self._lock("ContainerLifecycleManager.get_container_metadata_by_ip"):
            for container_id, container_meta in list[tuple](self.container_metadata.items()):  # Use list() here too
                # logger.debug(f"Checking Container {C.MAGENTA}{container_id}{C.RESET}, State:{container_meta.state} Fucntion:{container_meta.function_name}")
                if not container_meta.ip_address and container_meta.state == ContainerState.STARTING:
                    try:
                        # Query Docker to get the actual IP for this container
                        docker_container = self.docker_client.containers.get(container_id)
                        docker_container.reload()
                    except docker.errors.NotFound:
                        # Container was removed, skip it
                        logger.debug(f"Container {C.MAGENTA}{container_id}{C.RESET} not found in Docker during IP lookup fallback (may have been removed)")
                        continue
                    except Exception as e:
                        logger.debug(f"Could not query Docker for container {C.MAGENTA}{container_id}{C.RESET}: {e}")

        with self._lock("ContainerLifecycleManager.get_container_metadata_by_ip"):
            # First, try direct IP match
            for container_id, container_meta in list(self.container_metadata.items()):  # Use list() to create snapshot
                if container_meta.ip_address == container_ip and container_meta.state in [ContainerState.STARTING, ContainerState.READY, ContainerState.LEASED]:
                    logger.debug(f"Client IP Lookup matched : {container_ip} -> {container_meta}")
                    return container_meta

            return None

    def get_status(self):
        """Get current status of the lifecycle manager"""
        with self._lock("ContainerLifecycleManager.get_status"):
            status = {
                'running': self.running,
                'function_configs': self.function_configs,
                'active_containers': list(self.container_function_map.keys()),
                'starting_containers': json.dumps([meta.container_name for meta in self.container_metadata.values() if meta.state == ContainerState.STARTING]),
                'container_metadata': {
                    cid: {
                        'container_id': meta.container_id,
                        'container_name': meta.container_name,
                        'function_name': meta.function_name,
                        'ip_address': meta.ip_address,
                        'init_start_time': meta.init_start_time,
                        'init_end_time': meta.init_end_time,
                        'init_duration_ms': meta.get_init_duration_ms(),
                        'state': str(meta.get_state())
                    }
                    for cid, meta in self.container_metadata.items()
                },
                'invocation_timing': self._invocation_timing,
                'invocation_responses': len(self._invocation_responses),
                'invocation_queues': len(self._invocation_queues),
                # 'invocations': self.invocation,
                'container_function_map': len(self.container_function_map),
            }
        return status

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self._check_all_functions()
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}", exc_info=True)

            time.sleep(self.check_interval)

    def _check_all_functions(self):
        """Check all functions and scale as needed"""
        # Refresh configs from database first to pick up external changes - maybe we push the changes on update later
        self._refresh_function_configs()

        # Clean up zombie invocations FIRST
        self._cleanup_zombie_invocations()

        # Get all Lambda functions from database
        functions = self.db.list_functions_from_db()

        for func in functions:
            function_name = func['FunctionName']
            try:
                self._cleanup_stopped_containers(function_name)
            except Exception as e:
                logger.error(f"Error cleaning up containers for {function_name}: {e}", exc_info=True)

            try:
                self._manage_function_scaling(function_name)
            except Exception as e:
                logger.error(f"Error managing function {function_name}: {e}", exc_info=True)

        self._terminate_draining_containers()

    def _terminate_draining_containers(self):
        """Terminate containers that are in DRAINING state and safe to kill"""
        for cid, container_metadata in list(self.container_metadata.items()):
            if container_metadata.state != ContainerState.DRAINING:
                continue

            # Only terminate if not actively processing (RUNNING)
            if container_metadata.state == ContainerState.RUNNING:
                logger.debug(f"Skipping termination of {container_metadata.container_name} - still RUNNING")
                continue

            try:
                container = self.docker_client.containers.get(container_metadata.container_id)

                # Double-check container status
                if container.status != 'running':
                    logger.info(f"Container {C.YELLOW}{container_metadata.container_name}{C.RESET} already stopped")
                    self.unregister_container(container_metadata.container_id)
                    continue

                # Safe to terminate - container is DRAINING and not RUNNING
                logger.info(f"Terminating DRAINING container {C.YELLOW}{container_metadata.container_name}{C.RESET} (state: {container_metadata.state})")
                success = self.stop_container_gracefully(container)

                if not success:
                    logger.warning(f"Failed to stop {container_metadata.container_name} gracefully, will retry next cycle")

            except docker.errors.NotFound:
                logger.info(f"Container {container_metadata.container_name} already removed")
                self.unregister_container(container_metadata.container_id)
            except Exception as e:
                logger.error(f"Error terminating container {container_metadata.container_name}: {e}", exc_info=True)

    def _cleanup_zombie_invocations(self):
        """Clean up invocations that have been waiting too long (likely orphaned)"""
        now = time.time()
        max_wait = 120  # 2 minutes - if an invocation has been waiting this long, something is wrong

        with self._lock("ContainerLifecycleManager._cleanup_zombie_invocations"):
            # Find zombie invocations that started too long ago
            zombies = []
            for request_id, start_time in list(self.invocation_timing.items()):
                wait_time = now - start_time
                if wait_time > max_wait:
                    zombies.append((request_id, wait_time))

            # Clean them up
            for request_id, wait_time in zombies:
                logger.warning(f"Cleaning up zombie invocation {C.CYAN}{request_id}{C.RESET} (waited {wait_time:.1f}s)")

                # Remove from timing
                self.invocation_timing.pop(request_id, None)

                # Mark as timed out if not already responded
                if request_id not in self.invocation_responses:
                    self.invocation_responses[request_id] = {
                        'statusCode': 504,
                        'body': {
                            'errorType': 'InvocationTimeout',
                            'errorMessage': f'Invocation timed out after {wait_time:.1f}s - container may have crashed'
                        },
                        'timestamp': now,
                        'duration_ms': wait_time * 1000
                    }
                    logger.info(f"Marked zombie invocation {C.CYAN}{request_id}{C.RESET} as timed out")

    def _cleanup_stopped_containers(self, function_name):
        """Clean up stopped containers"""
        containers = self._get_function_containers(function_name, status='exited')

        for container in containers:
            # Skip containers that are currently being started (check via metadata state)
            cid = getattr(container, 'id', None)
            container_metadata = self.container_metadata.get(cid)
            if container_metadata and container_metadata.state == ContainerState.STARTING:
                if container.status == 'running':
                    logger.info(f"Skipping cleanup of {C.YELLOW}{container.name}{C.RESET} - currently starting")
                    continue

            # try:
                # Get container exit info before removing for logging
                # try:
                #     container.reload()
                # except docker.errors.NotFound:
                #     logger.warning(f"Container {C.YELLOW}{container.name}{C.RESET} not found during cleanup")
                #     continue
                # exit_code = container.attrs.get('State', {}).get('ExitCode', 0)

                # # Log failures for debugging
                # if exit_code != 0:
                #     logs = container.logs(tail=50).decode(errors='ignore')
                #     logger.error(f"Container {C.YELLOW}{container.name}{C.RESET} for {function_name} exited with code {exit_code}")
                #     logger.error(f"Last 50 lines of logs:\n{logs}")

                #     # Clean up any pending invocations for this container
                #     self._cleanup_container_invocations(container.id)

            try:
                container.remove()
            except docker.errors.NotFound:
                logger.warning(f"Container {C.YELLOW}{container.name}{C.RESET} already removed")
                continue

            # Clean up activity tracking (use container ID)
            with self._lock("ContainerLifecycleManager._cleanup_stopped_containers"):
                self.container_activity.pop(getattr(container, 'id', None), None)

            #     logger.info(f"Removed stopped container {C.YELLOW}{container.name}{C.RESET} for function {function_name}")

            # except Exception as e:
            #     logger.error(f"Failed to remove container: {C.YELLOW}{container.name}{C.RESET} -> {e}")

    def _cleanup_container_invocations(self, container_id):
        """Clean up any pending invocations for a crashed container"""
        with self._lock("ContainerLifecycleManager._cleanup_container_invocations"):
            # Find the function name for this container
            function_name = self.container_function_map.get(container_id)
            if not function_name:
                return

            logger.warning(f"Cleaning up invocations for crashed container {C.MAGENTA}{container_id}{C.RESET} (function: {function_name})")

            # Mark all pending invocations for this function as failed
            # (We can't know for sure which invocations were being processed by this specific container,
            # so we'll let the zombie cleanup handle timing out old invocations)

            # Just log for now - the zombie cleanup will handle the actual timeout
            pending_count = len([rid for rid, start in self.invocation_timing.items()
                                if rid not in self.invocation_responses])
            if pending_count > 0:
                logger.warning(f"Container crash detected - {pending_count} invocations may be orphaned and will timeout")

    def _manage_function_scaling(self, function_name):
        """Manage scaling for a specific function"""
        config = self.function_configs[function_name]

        # Get current running containers (only count READY and LEASED, not STARTING/DRAINING)
        containers = self._get_function_containers(function_name, status='running')

        # Filter to only count containers in usable states
        ready_count = 0
        for container in containers:
            cid = getattr(container, 'id', None)
            container_metadata = self.container_metadata.get(cid)
            if container_metadata and container_metadata.state in [ContainerState.READY, ContainerState.LEASED, ContainerState.RUNNING]:
                ready_count += 1

        current_count = ready_count

        # Get queue depth
        queue_depth = self._get_queue_depth(function_name)

        # Maintain provisioned capacity - minimum instances
        if current_count < config['provisioned']:
            needed = config['provisioned'] - current_count
            logger.info(f"Provisioned capacity for {function_name}: scaling {current_count} -> {config['provisioned']} (+{needed} instances)")
            for _ in range(needed):
                self._start_container_instance(function_name)
            # Update current count after provisioning
            current_count = config['provisioned']

        # Only scale if queue demands it AND we haven't hit reserved limit
        if queue_depth > config['scale_up_threshold'] and current_count < config['reserved']:
            needed = min(
                queue_depth - current_count,  # Scale based on queue
                config['reserved'] - current_count  # But don't exceed reserved limit
            )
            logger.info(f"Queue-based scaling for {function_name}: Current:{current_count} -> +{needed} (queue:{queue_depth}, threshold:{config['scale_up_threshold']})")
            for _ in range(needed):
                self._start_container_instance(function_name)

        # Only consider scale-down if we're above provisioned capacity
        elif current_count > config['provisioned']:
            logger.debug(f"Checking idle containers for {function_name} (current:{current_count} > provisioned:{config['provisioned']})")
            self._scale_down_idle_containers(function_name, config)

    def _scale_down_idle_containers(self, function_name, config):
        """Mark idle containers as DRAINING - actual termination happens in cleanup phase"""
        containers = self._get_function_containers(function_name, status='running')
        now = time.time()

        for container in containers:
            # Don't scale below provisioned capacity
            current_count = len(self._get_function_containers(function_name, status='running'))
            if current_count <= config['provisioned']:
                logger.debug(f"At provisioned capacity ({current_count}), skipping scale-down")
                break

            cid = getattr(container, 'id', None)
            container_metadata = self.container_metadata.get(cid)

            # Skip if already draining or no metadata
            if not container_metadata or container_metadata.state == ContainerState.DRAINING:
                continue

            # Skip if container is actively running an invocation
            if container_metadata.state == ContainerState.RUNNING:
                logger.debug(f"Skipping {container.name} - actively processing invocation")
                continue

            # Skip containers that are still starting up
            if container_metadata.state == ContainerState.STARTING:
                logger.debug(f"Skipping {container.name} - still starting up")
                continue

            # Check idle time - use container_activity if available, otherwise use metadata.last_activity
            last_active = self.container_activity.get(cid)
            if last_active is None:
                # Fallback to metadata last_activity if container_activity not set
                last_active = container_metadata.last_activity
                if last_active is None or last_active == 0:
                    # If still no valid time, use init_start_time as last resort
                    last_active = container_metadata.init_start_time

            idle_time = now - last_active

            if idle_time > config['idle_timeout']:
                logger.info(f"Marking container {C.YELLOW}{container.name}{C.RESET} as DRAINING (idle {idle_time:.0f}s, state: {container_metadata.state})")
                lifecycle_manager.update_container_state(container_metadata.container_id, ContainerState.DRAINING)

    def _get_function_containers(self, function_name, status=None):
        """Get containers for a function using Docker labels"""
        filters = {
            'label': [
                'localcloud=true',
                f'function-name={function_name}'
            ]
        }

        if status:
            filters['status'] = status

        try:
            return self.docker_client.containers.list(all=(status is None), filters=filters)
        except Exception as e:
            logger.error(f"Error listing containers for {function_name}: {e}")
            return []

    def _get_queue_depth(self, function_name):
        """Get current queue depth for a function"""
        if function_name not in self.invocation_queues:
            return 0
        return self.invocation_queues[function_name].qsize()

    def start_container_with_verification(self, function_name, max_attempts=3):
        """
        Start a container and verify it's ready.
        Returns container_name on success, None on failure.
        """
        logger.info(f"Starting container for {function_name}")

        # Start container (it handles verification internally now)
        container_name = self._start_container_instance(function_name)

        if container_name is None:
            logger.error(f"Failed to start container for {function_name}")
            return None

        # Container already verified by _start_container_instance
        logger.info(f"Container {C.YELLOW}{container_name}{C.RESET} started and verified")
        return container_name

    def _start_container_instance(self, function_name):
        """Start a new container instance for a function"""

        function_config = self.db.get_function_from_db(function_name)
        if not function_config:
            logger.error(f"Cannot start container: function {function_name} not found")
            return None

        runtime = function_config.get('Runtime', 'python3.11')
        image_uri = function_config.get('ImageUri')
        handler = function_config.get('Handler', 'lambda_function.handler')
        environment = function_config.get('Environment', {})

        # Get custom log group if configured
        log_group_name = function_config.get('LoggingConfig', {}).get('LogGroup')

        # Try to recover function_path for ZIP-based functions
        function_path = None
        if not image_uri and function_config.get('PackageType', '').lower() == 'zip':
            possible_dir = Path(FUNCTIONS_DIR) / function_name
            if possible_dir.exists() and any(possible_dir.iterdir()):
                function_path = possible_dir
                logger.info(f"Recovered function path for {function_name}: {function_path}")
            else:
                logger.error(f"No code directory found for ZIP function {function_name} at {possible_dir}")
                return None

        instance_id = uuid.uuid4().hex[:8]

        try:
            endpoint, container_name, _, err_resp, err_code = self.start_lambda_container(
                function_name,
                runtime=runtime,
                image_uri=image_uri,
                function_path=function_path,
                handler=handler,
                environment=environment,
                instance_id=instance_id,
                log_group_name=log_group_name,
                verify_ready=True
            )

            if err_resp:
                logger.error(f"Failed to start container: {err_code} - {err_resp}")
                return None

            logger.info(f"Started container instance: {C.YELLOW}{container_name}{C.RESET} endpoint: {endpoint}")
            return container_name

        except Exception as e:
            logger.error(f"Error starting container for {function_name}: {e}", exc_info=True)
            return None

    def stop_container_gracefully(self, container, timeout=900):
        """Stop a container gracefully with timeout - respects container state"""
        try:
            cid = getattr(container, 'id', None)
            container_metadata = self.container_metadata.get(cid)

            # Check if container is actively processing an invocation
            if container_metadata and container_metadata.state == ContainerState.RUNNING:
                logger.warning(f"Refusing to stop {C.YELLOW}{container.name}{C.RESET} - actively processing invocation (state: RUNNING)")
                return False

            # Only proceed if container is in a safe state (READY, LEASED, DRAINING)
            if container_metadata and container_metadata.state not in [ContainerState.READY, ContainerState.LEASED, ContainerState.DRAINING, ContainerState.TERMINATED]:
                logger.warning(f"Unsafe to stop {C.YELLOW}{container.name}{C.RESET} - state: {container_metadata.state}")
                return False

            logger.info(f"Gracefully stopping container {C.YELLOW}{container.name}{C.RESET} (state: {container_metadata.state if container_metadata else 'unknown'})")

            # Stop the logger FIRST to prevent connection error logs
            self.log_manager.stop_container_logging(container.name)

            # Deregister container so no new jobs are sent to it
            self.unregister_container(container.id)

            # Kill and remove container
            container.kill(signal='SIGKILL')
            container.remove(force=True)

            # Clean up activity tracking
            with self._lock("ContainerLifecycleManager.stop_container_gracefully"):
                self.container_activity.pop(cid, None)

            # Mark as terminated
            # if container_metadata:
            #     lifecycle_manager.update_container_state(container_metadata.container_id, ContainerState.TERMINATED)

            logger.info(f"Successfully stopped container {C.YELLOW}{container.name}{C.RESET}")
            return True

        except Exception as e:
            logger.error(f"Error stopping container {C.YELLOW}{container.name}{C.RESET}: {e}")
            return False

    def mark_invocation_complete(self, request_id, response_data):
        """Store the response for a given invocation request ID"""
        with self._lock("ContainerLifecycleManager.mark_invocation_complete"):
            # INVOCATION_RESPONSES[request_id] = response_data
            # INVOCATION_TIMING.pop(request_id, None)

            # Calculate actual invocation duration
            invocation_duration_ms = None
            if request_id in self.invocation_timing:
                start_time = self.invocation_timing.pop(request_id)
                invocation_duration_ms = (time.time() - start_time) * 1000

            # Store the response with timing
            self.invocation_responses[request_id] = {
                'statusCode': 200,
                'body': response_data,
                'timestamp': time.time(),
                'duration_ms': invocation_duration_ms
            }

    def mark_invocation_error(self, request_id, error_data):
        """Store an error response for a given invocation request ID"""
        with self._lock("ContainerLifecycleManager.mark_invocation_error"):
            # INVOCATION_RESPONSES[request_id] = error_data
            # INVOCATION_TIMING.pop(request_id, None)

            # Calculate actual invocation duration
            invocation_duration_ms = None
            if request_id in self.invocation_timing:
                start_time = self.invocation_timing.pop(request_id)
                invocation_duration_ms = (time.time() - start_time) * 1000

            # Store the error with timing
            self.invocation_responses[request_id] = {
                'statusCode': 500,
                'body': error_data,
                'timestamp': time.time(),
                'duration_ms': invocation_duration_ms
            }

    def wait_for_invocation_response(self, request_id, is_cold_start: bool, container_id: str, init_duration_ms: int, timeout: int, include_logs):
        """Wait for an invocation response with timeout"""
        # Wait for response with reasonable timeout
        start_time = time.time()
        last_log_time = start_time
        init_duration_ms = 0

        while (time.time() - start_time) < timeout:
            # Log progress every 5 seconds to help debug hangs
            if time.time() - last_log_time > 5:
                elapsed = time.time() - start_time
                logger.warning(f"Still waiting for response {C.CYAN}{request_id}{C.RESET} after {elapsed:.1f}s (timeout: {timeout}s)")
                last_log_time = time.time()

            if self.invocation_responses:
                logger.debug(f"Existing requests: {self.invocation_responses}")
            if request_id in self.invocation_responses:
                response = self.invocation_responses.pop(request_id)

                # Get actual invocation duration from response
                duration_ms = response.get('duration_ms', 0)

                # Get init duration if cold start
                if is_cold_start and container_id:
                    metadata = self.get_container_metadata(container_id)
                    if metadata:
                        init_duration_ms = metadata.get_init_duration_ms()

                logger.info(f"Got response for RequestId:{C.CYAN}{request_id}{C.RESET} status={response['statusCode']} after {time.time()-start_time:.2f}s")

                # Build response headers
                headers = {
                    'Content-Type': 'application/json',
                    'X-Amz-Executed-Version': '$LATEST',
                    'X-Amz-Request-Id': request_id
                }

                # Only include logs if LogType=Tail was requested
                if include_logs:
                    log_output = self.log_manager.get_logs_with_report(
                        request_id,
                        duration_ms=duration_ms,
                        init_duration_ms=init_duration_ms,
                        memory_size_mb=128
                    )
                    # AWS returns base64-encoded logs in X-Amz-Log-Result header
                    headers['X-Amz-Log-Result'] = base64.b64encode(log_output.encode()).decode()
                    logger.info(f"Including logs in response for {C.CYAN}{request_id}{C.RESET}")

                # Write END line to CloudWatch
                if container_id:
                    metadata = self.get_container_metadata(container_id)
                    if metadata:
                        log_config = self.log_manager.container_log_config.get(container_id, {})
                        log_group = log_config.get('log_group')
                        log_stream = log_config.get('log_stream')

                        if log_group and log_stream:
                            self.log_manager.write_end_line(request_id, log_group, log_stream)

                if log_group and log_stream:
                    billed_duration = max(100, int((duration_ms + 99) / 100) * 100)
                    report_parts = [
                        f"REPORT RequestId: {request_id}",
                        f"\tDuration: {duration_ms:.2f} ms",
                        f"\tBilled Duration: {billed_duration} ms",
                        f"\tMemory Size: 128 MB",
                        f"\tMax Memory Used: 128 MB"
                    ]
                    if is_cold_start and init_duration_ms:
                        report_parts.insert(1, f"\tInit Duration: {init_duration_ms:.2f} ms")

                    report_line = '\t'.join(report_parts)

                    # put_log_events expects a list of event dicts
                    self.log_manager.logs_db.put_log_events(log_group, log_stream, [{
                        'timestamp': int(time.time() * 1000),
                        'message': report_line
                    }])

                # Write REPORT line to CloudWatch
                self.log_manager.container_logs(
                    request_id,
                    duration_ms,
                    init_duration_ms=init_duration_ms
                )
                try:
                    lifecycle_manager.update_container_state(container_id, ContainerState.READY)
                except KeyError:
                    pass
                return response['body'], response['statusCode'], headers

            time.sleep(0.1)

        # Timeout reached
        elapsed = time.time() - start_time
        logger.error(f'RequestId:{C.CYAN}{request_id}{C.RESET} Timeout reached: {elapsed:.1f}s / {timeout}s - Response never received!')

        # Check if response arrived just after timeout
        if request_id in self.invocation_responses:
            self.invocation_responses.pop(request_id)
            logger.error(f"Response for {C.CYAN}{request_id}{C.RESET} arrived RIGHT after timeout - race condition!")

        try:
            with self._lock("ContainerLifecycleManager.wait_for_invocation_response"):
                lifecycle_manager.update_container_state(container_id, ContainerState.READY)
        except KeyError:
            pass
        # Return timeout error
        return {
            'errorType': 'TimeoutError',
            'errorMessage': f'Invocation timed out after {elapsed:.1f} seconds'
        }, 504, {
            'Content-Type': 'application/json',
            'X-Amz-Request-Id': request_id
        }

    def kill_container(self, container):
        """Kill a container forcefully"""
        try:
            self.log_manager.stop_container_logging(container.name)

            if container.status:
                container.kill()
                logger.info(f"Killed container {C.YELLOW}{container.name}{C.RESET}")
        except docker.errors.NotFound:
            pass

        try:
            with self._lock("ContainerLifecycleManager.kill_container"):
                self.container_activity.pop(getattr(container, 'id', None), None)
        except:
            pass

    def _graceful_shutdown_all(self, timeout=900):
        """Gracefully shutdown all localcloud containers"""
        try:
            containers = self.docker_client.containers.list(
                filters={'label': 'localcloud=true'}
            )

            logger.info(f"Gracefully shutting down {len(containers)} containers...")
            for container in containers:
                self.stop_container_gracefully(container, timeout)

        except Exception as e:
            logger.error(f"Error during graceful shutdown: {e}", exc_info=True)

    def mark_container_active(self, container_id):
        """Mark a container as active (called when processing invocation)"""
        with self._lock("ContainerLifecycleManager.mark_container_active"):
            ts = time.time()
            # Store activity keyed by container ID
            self.container_activity[container_id] = ts

            # Also store activity keyed by container name if we have metadata
            meta = self.get_container_metadata(container_id)
            if meta and getattr(meta, 'container_name', None):
                self.container_activity[meta.container_name] = ts

    def start_lambda_container(self, function_name, runtime='python3.11', image_uri=None,
                            function_path=None, handler='lambda_function.handler', environment=None,
                            command=None, entrypoint=None, workdir=None,
                            timeout=300, memory_size=128,
                            instance_id=None, log_group_name=None,
                            verify_ready=True):
        """Start a Lambda container with Runtime API support"""

        # Generate instance ID if not provided
        if instance_id is None:
            instance_id = uuid.uuid4().hex[:8]

        container_name = f"localcloud-lambda-{function_name}-{instance_id}"

        # Use custom log group or default
        if log_group_name is None:
            log_group_name = f'/aws/lambda/{function_name}'

        # Generate log stream name with CURRENT date
        current_date = datetime.now(timezone.utc).strftime('%Y/%m/%d')
        log_stream_name = f'{current_date}/[$LATEST]{instance_id}'

        try:
            if not image_uri and not function_path:
                logger.error(f"Either ImageUri or function code must be provided")
                return None, None, None, {
                    '__type': 'InvalidParameterValueException',
                    'message': 'Either ImageUri or function code must be provided'
                }, 400

            # Build image if code path provided
            if function_path:
                dockerfile = function_path / 'Dockerfile'
                dockerfile.write_text(self.create_dockerfile_for_runtime(runtime, handler))
                image_tag = f"lambda-{function_name}:latest"
                try:
                    logger.info(f"Building image from {function_path}")
                    _, logs = self.docker_client.images.build(path=str(function_path), nocache=True, tag=image_tag, rm=True)
                    for log in logs:
                        if 'stream' in log:
                            logger.info(log['stream'].strip())
                except docker.errors.BuildError as e:
                    logger.error(f"Build error: {e}")
                    return None, None, None, {
                        '__type': 'InvalidParameterValueException',
                        'message': f"Failed to build image: {e}"
                    }, 400
                image_uri = image_tag

            # Setup CloudWatch logging BEFORE starting container
            try:
                self.log_manager.create_log_group(log_group_name)
            except Exception as e:
                logger.error(f"CRITICAL: Failed to setup CloudWatch logging: {e}", exc_info=True)
                if verify_ready:
                    return None, None, None, {
                        '__type': 'ServiceException',
                        'message': f'Failed to setup CloudWatch logging: {e}'
                    }, 500

            try:
                logger.info(f"Starting Lambda container '{C.YELLOW}{container_name}{C.RESET}'")

                # Build complete AWS Lambda environment variables
                runtime_api_host = LOCALCLOUD_API_HOSTNAME
                if LOCALCLOUD_API_HOSTNAME in ('host.docker.internal', 'localhost', '127.0.0.1'):
                    runtime_api_host = 'lambda'

                container_env = {
                    'AWS_LAMBDA_FUNCTION_NAME': function_name,
                    'AWS_LAMBDA_FUNCTION_VERSION': '$LATEST',
                    'AWS_REGION': REGION,
                    'AWS_DEFAULT_REGION': REGION,
                    'AWS_EXECUTION_ENV': f'AWS_Lambda_{runtime}',
                    'AWS_LAMBDA_RUNTIME_API': f'{runtime_api_host}:4566',
                    'AWS_ENDPOINT_URL': f'http://{LOCALCLOUD_API_HOSTNAME}:4566',
                    'AWS_ENDPOINT_URL_S3': f'http://s3:9000',
                    '_HANDLER': handler,
                    'AWS_LAMBDA_FUNCTION_MEMORY_SIZE': str(memory_size),
                    'AWS_LAMBDA_FUNCTION_TIMEOUT': str(timeout),
                    'AWS_LAMBDA_LOG_GROUP_NAME': log_group_name,
                    'AWS_LAMBDA_LOG_STREAM_NAME': log_stream_name,
                    'AWS_LAMBDA_INITIALIZATION_TYPE': 'on-demand',
                    'LAMBDA_TASK_ROOT': '/var/task',
                    'LAMBDA_RUNTIME_DIR': '/var/runtime',
                    'AWS_ACCESS_KEY_ID': 'localcloud',
                    'AWS_SECRET_ACCESS_KEY': 'localcloud',
                    'AWS_SESSION_TOKEN': '',
                    'LANG': 'en_US.UTF-8',
                    'TZ': ':UTC',
                    'PATH': '/var/lang/bin:/usr/local/bin:/usr/bin/:/bin:/opt/bin',
                    'LD_LIBRARY_PATH': '/var/lang/lib:/lib64:/usr/lib64:/var/runtime:/var/runtime/lib:/var/task:/var/task/lib:/opt/lib',
                    'NODE_PATH': '/opt/nodejs/node_modules:/opt/nodejs/node14/node_modules:/var/runtime/node_modules:/var/runtime:/var/task',
                }

                # Merge user-provided environment variables
                if environment and isinstance(environment, dict):
                    container_env.update(environment)

                # Build container run parameters
                container_params = {
                    'image': image_uri,
                    'name': container_name,
                    'detach': True,
                    'network': LOCALCLOUD_NETWORK_NAME,
                    'extra_hosts': {
                        "host.docker.internal": "host-gateway"
                    },
                    'environment': container_env,
                    'labels': {
                        'localcloud': 'true',
                        'function-name': function_name,
                        'instance-id': instance_id
                    },
                    'log_config': {'Type': 'json-file', 'Config': {'max-size': '10m', 'max-file': '3'}}
                }

                # Only add command/entrypoint/workdir if specified
                if command:
                    container_params['command'] = command
                if entrypoint:
                    container_params['entrypoint'] = entrypoint
                if workdir:
                    container_params['working_dir'] = workdir

                container = self.docker_client.containers.run(**container_params, auto_remove=False)

                # Register container IMMEDIATELY after starting (before it can call runtime_next())
                # This prevents race condition where container polls before registration
                self.register_container(
                    container_id=container.id,
                    container_name=container.name,
                    function_name=function_name,
                    ip_address='',  # Will be updated once IP is available
                    state=ContainerState.STARTING
                )

                # Set container_activity immediately to prevent false idle timeout
                # This ensures the container has a valid activity time even if scaling check happens early
                with self._lock("ContainerLifecycleManager.start_lambda_container"):
                    self.container_activity[container.id] = time.time()

                # Check if container is still registered (might have been removed by scaling logic)
                if container.id not in self.container_metadata:
                    logger.warning(f"Container {C.MAGENTA}{C.MAGENTA}{container.id}{C.RESET}{C.RESET} was unregistered before IP retrieval, skipping")
                    return None, None, None, {
                        '__type': 'RuntimeError',
                        'message': 'Container was removed during startup'
                    }, 400

                try:
                    container.reload()
                except docker.errors.NotFound:
                    # Container was removed or died
                    logger.error(f"Container {C.MAGENTA}{C.MAGENTA}{container.id}{C.RESET}{C.RESET} was removed or crashed before IP retrieval")
                    if container.id in self.container_metadata:
                        self.unregister_container(container.id)
                    return None, None, None, {
                        '__type': 'RuntimeError',
                        'message': 'Container was removed during startup'
                    }, 400

                # Get container IP and update registration
                ip_addr = None
                max_retries = 3
                for retry in range(max_retries):
                    # Check if container is still registered before each retry
                    if container.id not in self.container_metadata:
                        logger.warning(f"Container {C.MAGENTA}{C.MAGENTA}{container.id}{C.RESET}{C.RESET} was unregistered during IP retrieval")
                        return None, None, None, {
                            '__type': 'RuntimeError',
                            'message': 'Container was removed during startup'
                        }, 400

                    try:
                        ip_addr = container.attrs['NetworkSettings']['Networks'][LOCALCLOUD_NETWORK_NAME]['IPAddress']
                        if ip_addr:
                            break
                    except (KeyError, TypeError) as e:
                        if retry < max_retries - 1:
                            time.sleep(0.1)
                            try:
                                container.reload()
                            except docker.errors.NotFound:
                                logger.warning(f"Container {C.MAGENTA}{C.MAGENTA}{container.id}{C.RESET}{C.RESET} was removed during IP retrieval retry")
                                if container.id in self.container_metadata:
                                    self.unregister_container(container.id)
                                return None, None, None, {
                                    '__type': 'RuntimeError',
                                    'message': 'Container was removed during startup'
                                }, 400
                            continue
                        logger.error(f"Failed to get IP address after {max_retries} retries: {e}")
                    except docker.errors.NotFound:
                        logger.warning(f"Container {C.MAGENTA}{container.id}{C.RESET} was removed during IP retrieval")
                        if container.id in self.container_metadata:
                            self.unregister_container(container.id)
                        return None, None, None, {
                            '__type': 'RuntimeError',
                            'message': 'Container was removed during startup'
                        }, 400
                    except Exception as e:
                        logger.error(f"Failed to get IP address: {e}")
                        if verify_ready:
                            logs = None
                            try:
                                logs = container.logs(tail=100).decode(errors='ignore')
                            except Exception:
                                logs = '<no logs available>'
                            logger.error(f"Container failed to get network. Logs:\n{logs}")
                            self.unregister_container(container.id)
                            try:
                                container.remove(force=True)
                            except:
                                pass
                            return None, None, None, {
                                '__type': 'RuntimeError',
                                'message': f'Container failed to start. IP address not found.'
                            }, 400

                # Update IP address in registration
                if ip_addr:
                    self.update_container_ip(container.id, ip_addr)
                    logger.info(f"ContainerId:{C.MAGENTA}{container.id}{C.RESET} ContainerName:{C.YELLOW}{container.name}{C.RESET} started with NetAddr: {ip_addr}")
                else:
                    logger.warning(f"ContainerId:{C.MAGENTA}{container.id}{C.RESET} ContainerName:{C.YELLOW}{container.name}{C.RESET} started but IP address not yet available")

                # Note: container_activity was already set during registration
                # Container state is tracked in ContainerMetadata, no need for separate starting_containers set

                # NOW start logging (after registration)
                logger.info(f"Starting log collection for {C.YELLOW}{container.name}{C.RESET}")
                try:
                    self.log_manager.start_container_logging(
                        container.id,
                        function_name,
                        log_group_name=log_group_name,
                        log_stream_name=log_stream_name
                    )
                    logger.info(f"Log collection started for {log_group_name}/{log_stream_name}")
                except Exception as e:
                    logger.error(f"CRITICAL: Failed to start log collection: {e}", exc_info=True)
                    if verify_ready:
                        try:
                            self.unregister_container(container.id)
                            container.remove(force=True)
                        except:
                            pass
                        return None, None, None, {
                            '__type': 'ServiceException',
                            'message': f'Failed to start log collection: {e}'
                        }, 500

                # Wait for container to be ready if requested
                if verify_ready:
                    # Check if container is still registered before reloading
                    if container.id not in self.container_metadata:
                        logger.warning(f"Container {C.MAGENTA}{container.id}{C.RESET} was unregistered before readiness check")
                        return None, None, None, {
                            '__type': 'RuntimeError',
                            'message': 'Container was removed during startup'
                        }, 400

                    try:
                        container.reload()
                    except docker.errors.NotFound:
                        # Container was removed (possibly by scaling logic)
                        logger.warning(f"Container {C.MAGENTA}{container.id}{C.RESET} was removed before readiness check")
                        if container.id in self.container_metadata:
                            self.unregister_container(container.id)
                        return None, None, None, {
                            '__type': 'RuntimeError',
                            'message': 'Container was removed during startup'
                        }, 400

                    if container.status != 'running':
                        logs = None
                        try:
                            logs = container.logs(tail=100).decode(errors='ignore')
                        except Exception:
                            logs = '<no logs available>'
                        logger.error(f"Container exited during startup:\n{logs}")
                        self.unregister_container(container.id)
                        return None, None, None, {
                            '__type': 'RuntimeError',
                            'message': 'Container exited during initialization'
                        }, 500

                    # Container is healthy - transition to READY
                    meta = self.container_metadata.get(container.id)
                    if meta:
                        lifecycle_manager.update_container_state(container.id, ContainerState.READY)
                        meta.init_end_time = time.time()
                        logger.info(f"Container {C.YELLOW}{container.name}{C.RESET} initialized and ready (init duration: {meta.get_init_duration_ms():.2f}ms)")

                # Return endpoint
                endpoint = f"http://{LOCALCLOUD_API_HOSTNAME}:4566/2015-03-31/functions/{function_name}/invocations"
                return endpoint, container_name, None, None, None

            except docker.errors.ImageNotFound as e:
                logger.error(f"Image not found: {e}")
                return None, None, None, {
                    '__type': 'InvalidParameterValueException',
                    'message': f"Image not found: {e}"
                }, 400
            except docker.errors.APIError as e:
                logger.error(f"API error: {e}")
                return None, None, None, {
                    '__type': 'InvalidParameterValueException',
                    'message': f"API error: {e}"
                }, 400
            except Exception as e:
                logger.error(f"Error starting container: {e}", exc_info=True)
                return None, None, None, {
                    '__type': 'ServiceException',
                    'message': str(e)
                }, 500
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return None, None, None, {
                '__type': 'ServiceException',
                'message': str(e)
            }, 500

    def create_dockerfile_for_runtime(self, runtime, handler):
        """Create Dockerfile content based on runtime"""

        if runtime.startswith('python'):
            return f"""FROM {RUNTIME_BASE_IMAGES.get(runtime, 'public.ecr.aws/lambda/python:3.12')}
COPY . ${{LAMBDA_TASK_ROOT}}
CMD [ "{handler}" ]
"""
        elif runtime.startswith('nodejs'):
            return f"""FROM {RUNTIME_BASE_IMAGES.get(runtime, 'public.ecr.aws/lambda/nodejs:22')}
COPY . ${{LAMBDA_TASK_ROOT}}
CMD [ "{handler}" ]
"""
        elif runtime.startswith('java'):
                    # Custom runtime - requires bootstrap file
                    return f"""FROM {RUNTIME_BASE_IMAGES.get(runtime, 'public.ecr.aws/lambda/java25')}
COPY . ${{LAMBDA_TASK_ROOT}}
RUN chmod +x ${{LAMBDA_TASK_ROOT}}/bootstrap || true
CMD [ "{handler}" ]
"""
        elif runtime.startswith('go'):
                    # Custom runtime - requires bootstrap file
                    return f"""FROM {RUNTIME_BASE_IMAGES.get(runtime, 'public.ecr.aws/lambda/go:1')}
COPY . ${{LAMBDA_TASK_ROOT}}
RUN chmod +x ${{LAMBDA_TASK_ROOT}}/bootstrap || true
CMD [ "{handler}" ]
"""
        elif runtime.startswith('provided'):
            # Custom runtime - requires bootstrap file
            return f"""FROM {RUNTIME_BASE_IMAGES.get(runtime, 'public.ecr.aws/lambda/provided:al2023')}
COPY . ${{LAMBDA_TASK_ROOT}}
RUN chmod +x ${{LAMBDA_TASK_ROOT}}/bootstrap || true
CMD [ "{handler}" ]
"""
        else:
            raise ValueError(f"Unsupported runtime: {runtime}")

    def wait_for_container_ready(self, container, timeout=30):
        """Wait for container to be running and polling for invocations"""
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                container.reload()

                # Check for exit early
                if container.status == 'exited':
                    logger.error(f"Container {C.YELLOW}{container.name}{C.RESET} exited during startup")
                    return False

                if container.status == 'running':
                    # Container is running - wait briefly to ensure Runtime API client initializes
                    logger.debug(f"Container {C.YELLOW}{container.name}{C.RESET} is running, waiting for Runtime API readiness...")
                    time.sleep(0.2)  # Give Runtime API client time to initialize

                    container.reload()
                    # Verify still running after settling period
                    if container.status == 'running':
                        logger.info(f"Container {C.YELLOW}{container.name}{C.RESET} verified ready")
                        return True
                    else:
                        logger.error(f"Container {C.YELLOW}{container.name}{C.RESET} changed status to {container.status}")
                        return False

            except docker.errors.NotFound:
                logger.error(f"Container disappeared during readiness check")
                return False
            except Exception as e:
                logger.error(f"Error checking container status: {e}")
                return False

            time.sleep(0.2)

        logger.error(f"Container readiness timeout after {timeout}s")
        return False

    def get_function_by_container_id(self, container_id):
        """Look up function name by container ID"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT function_name FROM container_mappings
            WHERE container_id = ?
        ''', (container_id,))

        row = cursor.fetchone()
        conn.close()

        return row[0] if row else None

    def save_container_mapping(self, function_name, container_id, container_ip):
        """Save container-to-function mapping in database"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO container_mappings
            (function_name, container_id, container_ip, created_at)
            VALUES (?, ?, ?, ?)
        ''', (function_name, container_id, container_ip,
            datetime.now(timezone.utc).isoformat()))

        conn.commit()
        conn.close()
        logger.info(f"Saved container mapping: {function_name} -> {C.MAGENTA}{C.MAGENTA}{container_id}{C.RESET}{C.RESET} ({container_ip})")

    def recover_existing_containers(self):
        """
        On startup, recover mappings for any running containers
        This handles the case where aws_api was restarted but containers are still running
        """
        try:
            containers = self.docker_client.containers.list(filters={'label': 'localcloud=true'})
            logger.info(f"Found {len(containers)} existing LocalCloud containers")

            for container in containers:
                function_name = container.labels.get('function-name')
                if not function_name:
                    logger.warning(f"Container {C.YELLOW}{container.name}{C.RESET} missing function-name label")
                    continue

                # Get container IP
                container.reload()
                container_ip = None
                networks = container.attrs.get('NetworkSettings', {}).get('Networks', {})
                for network_name, network_info in networks.items():
                    container_ip = network_info.get('IPAddress')
                    self.register_container(
                        container_id=container.id,
                        container_name=container.name,
                        function_name=function_name,
                        ip_address=container_ip,
                        state=ContainerState.READY
                    )
                    if container_ip:
                        break

                # Check if mapping exists in DB
                existing_function = self.get_function_by_container_id(container.name)
                if existing_function != function_name:
                    # Update/create mapping
                    self.save_container_mapping(function_name, container.name, container_ip)
                    logger.info(f"Recovered container mapping: {function_name} -> {C.YELLOW}{container.name}{C.RESET} ({container_ip})")
                else:
                    logger.info(f"Container mapping already exists for {function_name}")

        except Exception as e:
            logger.error(f"Error recovering containers: {e}", exc_info=True)

app = Flask(__name__)


def _get_client_ip():
    # Prefer X-Forwarded-For when present, else use remote_addr
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr


@app.route('/2015-03-31/functions/<function_name>/invocations', methods=['POST'])
def invoke_function(function_name):
    """Public invocation endpoint that emulates AWS Lambda invoke (synchronous).
    This queues the event for a runtime-polling container and waits for the response.
    """
    if not lifecycle_manager:
        return jsonify({'__type': 'ServiceException', 'message': 'Lifecycle not initialized'}), 500

    existing_function = lifecycle_manager.db.get_function_from_db(function_name)
    if not existing_function:
        return jsonify({'__type': 'ResourceNotFoundException', 'message': f'Function not found: {function_name}'})

    payload = request.get_data() or b''
    try:
        event = json.loads(payload.decode()) if payload else None
    except Exception:
        # If payload is not JSON, keep raw bytes as string
        event = payload.decode(errors='ignore')

    request_id = str(uuid.uuid4())
    logger.info(f"New invocation RequestId: {request_id}")
    include_logs = (request.headers.get('X-Amz-Log-Type', '') == 'Tail')

    # Ensure a container is running for this function
    running_containers = lifecycle_manager._get_function_containers(function_name, status='running')
    container_id = None
    is_cold = False

    # Build queue message
    message = {
        'request_id': request_id,
        'event': event,
        'context': {},
        'source': 'invoke-api'
    }

    lifecycle_manager.set_invocation_queue(function_name, message)

    # Record invocation start time
    with lifecycle_manager._lock("invoke_function.set_timing"):
        lifecycle_manager.invocation_timing[request_id] = time.time()

    if not running_containers:
        container_name = lifecycle_manager.start_container_with_verification(function_name)

        # Handle in case of container startup failure
        if not container_name:
            logger.error(f"Failed to start container for {function_name}, marking invocation as failed")

            # CRITICAL: Remove the message from queue to prevent infinite retry loop
            try:
                queue_obj = lifecycle_manager.get_invocation_queue(function_name)
                # Try to consume the message we just added
                try:
                    queue_obj.get_nowait()
                    logger.info(f"Removed failed invocation message from queue for {function_name}")
                except Empty:
                    logger.warning(f"Queue was already empty when trying to remove failed message")
            except Exception as e:
                logger.error(f"Error removing message from queue: {e}")

            # Remove from timing to prevent infinite retry
            with lifecycle_manager._lock("invoke_function.cleanup_failed"):
                lifecycle_manager.invocation_timing.pop(request_id, None)

            # Return error immediately
            error_response = {
                'errorType': 'ServiceException',
                'errorMessage': 'Failed to start Lambda container - function may have initialization errors'
            }

            return jsonify(error_response), 500

        try:
            c = docker_client.containers.get(container_name)
            container_id = c.id
        except Exception:
            container_id = None
        is_cold = True
    else:
        container_id = running_containers[0].id

    # Determine init duration if cold start
    init_duration_ms = None
    if is_cold and container_id:
        meta = lifecycle_manager.get_container_metadata(container_id)
        if meta:
            init_duration_ms = meta.get_init_duration_ms()

    # Wait for the function response
    try:
        body, status_code, headers = lifecycle_manager.wait_for_invocation_response(
            request_id,
            is_cold_start=is_cold,
            container_id=container_id,
            init_duration_ms=init_duration_ms or 0,
            timeout=int(os.getenv('FUNCTION_INVOKE_TIMEOUT', '900')),
            include_logs=include_logs,
        )

        # Handle error responses (status >= 400)
        if status_code >= 400:
            # For Lambda errors, the body contains the error details
            if isinstance(body, dict):
                # AWS Lambda returns function errors with specific headers
                if 'errorType' in body or 'errorMessage' in body:
                    headers['X-Amz-Function-Error'] = 'Unhandled'

                resp_body = json.dumps(body)
                if 'Content-Type' not in headers:
                    headers['Content-Type'] = 'application/json'
            else:
                resp_body = body if isinstance(body, str) else str(body)

            return Response(resp_body, status=status_code, headers=headers,
                          mimetype=headers.get('Content-Type', 'application/json'))

        # Handle success responses (status < 400)
        if isinstance(body, (dict, list)):
            resp_body = json.dumps(body)
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/json'
        else:
            resp_body = body if isinstance(body, str) else str(body)

        return Response(resp_body, status=status_code, headers=headers,
                       mimetype=headers.get('Content-Type', 'application/json'))

    except Exception as e:
        logger.error(f"Error waiting for invocation response: {e}", exc_info=True)
        return jsonify({'__type': 'ServiceException', 'message': str(e)}), 500


@app.route('/2015-03-31/functions', methods=['GET'], strict_slashes=False)
def list_functions():
    """List all Lambda functions"""
    try:
        logger.info('Listing all functions')
        functions = lifecycle_manager.db.list_functions_from_db()
        return jsonify({
            'Functions': functions,
            'NextMarker': None
        }), 200

    except Exception as e:
        logger.error(f"Error listing functions: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": f"Error listing functions - {e}"
        }), 500


@app.route('/2015-03-31/functions/<function_name>', methods=['GET'], strict_slashes=False)
def get_function(function_name):
    """Get function configuration"""
    try:
        logger.info(f"Getting function: {function_name}")

        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                "__type": "ResourceNotFoundException:",
                "message": f"Function not found: {function_name}"
            }), 404

        response_config = function_config.copy()
        response_config.pop('Endpoint', None)
        response_config.pop('ContainerName', None)
        response_config.pop('HostPort', None)

        return jsonify({
            'Configuration': response_config,
            'Code': {
                'RepositoryType': 'ECR' if response_config.get('PackageType') == 'Image' else 'S3',
                'ImageUri': response_config.get('ImageUri', '')
            }
        }), 200

    except Exception as e:
        logger.error(f"Error getting function {function_name}: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": f"Unhandled exception for function: {function_name} - {e}"
        }), 500


@app.route('/2015-03-31/functions/<function_name>', methods=['DELETE'], strict_slashes=False)
def delete_function(function_name):
    """Delete a Lambda function"""
    try:
        logger.info(f"Deleting function: {function_name}")

        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                "__type": "ResourceNotFoundException:",
                "message": f"Function not found: {function_name}"
            }), 404

        # Get ALL containers for this function (running, starting, ready, leased, etc.)
        all_containers = lifecycle_manager._get_function_containers(function_name, status=None)

        if all_containers:
            logger.info(f"Found {len(all_containers)} container(s) for {function_name}, transitioning to DRAINING")

            for container in all_containers:
                container_id = container.id
                container_meta = lifecycle_manager.get_container_metadata(container_id)

                if container_meta:
                    current_state = container_meta.state
                    logger.info(f"Transitioning container {container.name} from {current_state} to DRAINING")
                    lifecycle_manager.update_container_state(container_id, ContainerState.DRAINING)
                else:
                    # Container exists in Docker but not in our tracking - force remove
                    logger.warning(f"Container {container.name} not in metadata, forcing removal")
                    try:
                        lifecycle_manager.log_manager.stop_container_logging(container.name)
                        container.stop(timeout=3)
                        container.remove()
                    except Exception as e:
                        logger.warning(f"Error force-removing untracked container: {e}")
        else:
            logger.info(f"No containers found for {function_name}")

        # Delete from database - function is now unavailable for new invocations
        lifecycle_manager.db.delete_function_from_db(function_name)
        logger.info(f"Function deleted from database: {function_name}")
        logger.info(f"Containers will be terminated by lifecycle manager")

        return '', 204

    except Exception as e:
        logger.error(f"Error deleting function {function_name}: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": f"Unhandled exception for function: {function_name} - {e}"
        }), 500


@app.route('/2015-03-31/functions/<function_name>/configuration', methods=['GET'], strict_slashes=False)
def get_function_configuration(function_name):
    """Get Lambda function configuration"""
    try:
        logger.info(f"Getting function configuration: {function_name}")

        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                "__type": "ResourceNotFoundException:",
                "message": f"Function not found: {function_name}"
            }), 404

        response_config = function_config.copy()
        response_config.pop('Endpoint', None)
        response_config.pop('ContainerName', None)
        response_config.pop('HostPort', None)

        env_vars = response_config.get("Environment", {})
        if isinstance(env_vars, dict):
            response_config["Environment"] = {"Variables": env_vars}

        return jsonify(response_config), 200

    except Exception as e:
        logger.error(f"Error getting configuration for {function_name}: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": f"Unhandled exception for function: {function_name} - {e}"
        }), 500


@app.route('/2015-03-31/functions/<function_name>/configuration', methods=['PUT'], strict_slashes=False)
def update_function_configuration(function_name):
    """Update Lambda function configuration"""
    try:
        logger.info(f"Updating function configuration: {function_name}")

        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                "__type": "ResourceNotFoundException:",
                "message": f"Function not found: {function_name}"
            }), 404

        data = request.get_json() or {}

        # Update environment variables
        env_vars = data.get("Environment", {}).get("Variables")
        if env_vars and isinstance(env_vars, dict):
            function_config["Environment"] = env_vars

        if "LoggingConfig" in data:
            function_config["LoggingConfig"] = data["LoggingConfig"]

        # Optional updates
        for key in ["Handler", "Role", "Runtime", "Timeout", "MemorySize"]:
            if key in data:
                function_config[key] = data[key]

        # Save updated configuration
        lifecycle_manager.db.save_function_to_db(function_config)
        logger.info(f"Function configuration updated: {function_name}")

        response_config = function_config.copy()
        response_config.pop('Endpoint', None)
        response_config.pop('ContainerName', None)
        response_config.pop('HostPort', None)
        env_vars = response_config.get("Environment", {})
        if isinstance(env_vars, dict):
            response_config["Environment"] = {"Variables": env_vars}

        return jsonify(response_config), 200

    except Exception as e:
        logger.error(f"Error updating configuration for {function_name}: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": f"Unhandled exception for function: {function_name} - {e}"
        }), 500


@app.route('/2015-03-31/functions/<function_name>/code', methods=['PUT'], strict_slashes=False)
def update_function_code(function_name):
    """Update function code"""
    try:
        logger.info(f"Updating function code: {function_name}")

        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                "__type": "ResourceNotFoundException:",
                "message": f"Function not found: {function_name}"
            }), 404

        data = request.get_json() or {}
        image_uri = data.get('ImageUri')
        zip_file = data.get('ZipFile')

        if not image_uri and not zip_file:
            return jsonify({
                "__type": "InvalidParameterValueException:",
                "message": "Either ImageUri or ZipFile must be provided"
            }), 400

        # Stop old container
        container_name = function_config.get('ContainerName')
        if container_name:
            try:
                containers = lifecycle_manager.docker_client.containers.list(all=True, filters={"name": container_name})
                for container in containers:
                    lifecycle_manager.update_container_state(container.id, ContainerState.TERMINATED)
                    container.stop(timeout=3)
                    container.remove()
            except Exception as e:
                logger.warning(f"Error removing old container: {e}")

        runtime = function_config.get('Runtime', 'python3.11')
        handler = function_config.get('Handler', 'lambda_function.handler')
        environment = data.get('Environment', {}).get('Variables') or function_config.get('Environment', {})

        # Start new container
        if image_uri:
            endpoint, container_name, host_port, err_resp, err_code = lifecycle_manager.start_lambda_container(
                function_name,
                runtime=runtime,
                image_uri=image_uri,
                handler=handler,
                environment=environment,
                verify_ready=False
            )
            if err_resp:
                return err_resp, err_code

        elif zip_file:
            zip_data = base64.b64decode(zip_file)

            filename_hash = sha256(zip_file.encode('utf-8')).hexdigest()
            function_dir = FUNCTIONS_DIR / filename_hash
            function_dir.mkdir(exist_ok=True)

            zip_path = function_dir / 'function.zip'
            zip_path.write_bytes(zip_data)

            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(function_dir)

            endpoint, container_name, host_port, err_resp, err_code = lifecycle_manager.start_lambda_container(
                function_name,
                runtime=runtime,
                function_path=function_dir,
                handler=handler,
                environment=environment
            )
            if err_resp:
                return err_resp, err_code

        function_config['ContainerName'] = container_name
        function_config['HostPort'] = host_port
        function_config['Endpoint'] = endpoint
        function_config['Environment'] = environment

        if image_uri:
            function_config['ImageUri'] = image_uri
            function_config['CodeSha256'] = base64.b64encode(image_uri.encode()).decode()

        lifecycle_manager.db.save_function_to_db(function_config)
        logger.info(f"Function code updated: {function_name}")

        response_config = function_config.copy()
        response_config.pop('Endpoint', None)
        response_config.pop('ContainerName', None)
        response_config.pop('HostPort', None)

        return jsonify(response_config), 200

    except Exception as e:
        logger.error(f"Error updating code for {function_name}: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": f"Unhandled exception for function: {function_name} - {e}"
        }), 500


@app.route('/2015-03-31/functions/<function_name>/logging-config', methods=['GET'])
def get_function_logging_config(function_name):
    """Get function logging configuration"""
    try:
        logger.info(f"Getting logging config for: {function_name}")

        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                "__type": "ResourceNotFoundException:",
                "message": f"Function not found: {function_name}"
            }), 404

        log_config = function_config.get('LoggingConfig', {
            'LogFormat': 'Text',
            'ApplicationLogLevel': 'INFO',
            'SystemLogLevel': 'INFO',
            'LogGroup': f'/aws/lambda/{function_name}'
        })

        return jsonify(log_config), 200

    except Exception as e:
        logger.error(f"Error getting logging config: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": str(e)
        }), 500


@app.route('/2015-03-31/functions/<function_name>/logging-config', methods=['PUT'])
def put_function_logging_config(function_name):
    """Configure function logging"""
    try:
        logger.info(f"Setting logging config for: {function_name}")

        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                "__type": "ResourceNotFoundException:",
                "message": f"Function not found: {function_name}"
            }), 404

        data = request.get_json() or {}

        log_config = {
            'LogFormat': data.get('LogFormat', 'Text'),
            'ApplicationLogLevel': data.get('ApplicationLogLevel', 'INFO'),
            'SystemLogLevel': data.get('SystemLogLevel', 'INFO'),
            'LogGroup': data.get('LogGroup', f'/aws/lambda/{function_name}')
        }

        function_config['LoggingConfig'] = log_config
        lifecycle_manager.db.save_function_to_db(function_config)

        return jsonify(log_config), 200

    except Exception as e:
        logger.error(f"Error updating logging config: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": str(e)
        }), 500


@app.route('/2015-03-31/functions/<function_name>/logging-config', methods=['DELETE'])
def delete_function_logging_config(function_name):
    """Delete function logging configuration"""
    try:
        logger.info(f"Deleting logging config for: {function_name}")

        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                "__type": "ResourceNotFoundException:",
                "message": f"Function not found: {function_name}"
            }), 404

        if 'LoggingConfig' in function_config:
            del function_config['LoggingConfig']
            lifecycle_manager.db.save_function_to_db(function_config)

        return '', 204

    except Exception as e:
        logger.error(f"Error deleting logging config: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": str(e)
        }), 500


@app.route('/2019-09-30/functions/<function_name>/concurrency', methods=['GET']) # aws lambda get-function-concurrency
def get_function_concurrency(function_name):
    """Get provisioned concurrent settings"""
    try:
        logger.info(f"Getting function concurrency for: {function_name}")
        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                "__type": "ResourceNotFoundException:",
                "message": f"Function not found: {function_name}"
            }), 404

        provisioned = function_config.get('ReservedConcurrentExecutions', 0)
        return jsonify({
            'ReservedConcurrentExecutions': provisioned,
        }), 200
        # return jsonify(function_config), 200

    except Exception as e:
        logger.error(f"Error setting concurrency: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": str(e)
        }), 500


@app.route('/2019-09-30/functions/<function_name>/provisioned-concurrency', methods=['GET']) # aws lambda get-provisioned-concurrency-config
def get_provisioned_concurrency(function_name):
    """Get provisioned concurrent settings"""
    try:
        logger.info(f"Getting provisioned concurrency for: {function_name}")
        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                "__type": "ResourceNotFoundException:",
                "message": f"Function not found: {function_name}"
            }), 404
        logger.critical(f'function_config: {function_config}')
        # data = request.get_json() or {}
        provisioned = function_config.get('ProvisionedConcurrentExecutions', 0)

        # TODO erm, kind of fake but whatever
        return jsonify({
            'RequestedProvisionedConcurrentExecutions': provisioned,
            'AvailableProvisionedConcurrentExecutions': provisioned,
            'AllocatedProvisionedConcurrentExecutions': provisioned,
            'Status': 'READY',
            'LastModified': datetime.now(timezone.utc).isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Error setting concurrency: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": str(e)
        }), 500


@app.route('/2017-10-31/functions/<function_name>/concurrency', methods=['PUT']) # aws lambda put-function-concurrency
def put_function_concurrency(function_name):
    """Set reserved concurrent executions"""
    try:
        data = request.get_json() or {}
        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                "__type": "ResourceNotFoundException:",
                "message": f"Function not found: {function_name}"
            }), 404

        reserved = data.get('ReservedConcurrentExecutions', 0)
        function_config['ReservedConcurrency'] = reserved

        logger.info(f"Setting concurrency for Function:{function_name} Concurrency:{data} NewValue:{reserved}")
        lifecycle_manager.db.save_function_to_db(function_config)

        # lifecycle_manager.function_configs[function_name]['provisioned'] = provisioned_concurrent_executions
        # lifecycle_manager.function_configs[function_name]['reserved'] = data.get('ReservedConcurrentExecutions', 0)

        return jsonify({
            'ReservedConcurrentExecutions': reserved
        }), 200

    except Exception as e:
        logger.error(f"Error setting concurrency: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": str(e)
        }), 500


@app.route('/2019-09-30/functions/<function_name>/provisioned-concurrency', methods=['PUT']) # aws lambda put-provisioned-concurrency-config
def put_provisioned_concurrency(function_name):
    """Set provisioned concurrent executions"""
    try:
        logger.info(f"Setting provisioned concurrency for: {function_name}")

        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                "__type": "ResourceNotFoundException:",
                "message": f"Function not found: {function_name}"
            }), 404

        data = request.get_json() or {}
        provisioned = data.get('ProvisionedConcurrentExecutions', 0)

        function_config['ProvisionedConcurrency'] = provisioned
        lifecycle_manager.db.save_function_to_db(function_config)

        return jsonify({
            'RequestedProvisionedConcurrentExecutions': provisioned,
            'AvailableProvisionedConcurrentExecutions': provisioned,
            'AllocatedProvisionedConcurrentExecutions': provisioned,
            'Status': 'READY',
            'LastModified': datetime.now(timezone.utc).isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Error setting provisioned concurrency: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": str(e)
        }), 500


@app.route('/2019-09-30/functions/<function_name>/provisioned-concurrency', methods=['DELETE']) # aws lambda delete-provisioned-concurrency-config
def delete_provisioned_concurrency(function_name):
    """Set provisioned concurrent executions"""
    try:
        logger.info(f"Deleting provisioned concurrency for: {function_name}")

        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                "__type": "ResourceNotFoundException:",
                "message": f"Function not found: {function_name}"
            }), 404

        function_config['ProvisionedConcurrency'] = 0
        lifecycle_manager.db.save_function_to_db(function_config)

        return jsonify({}), 200

    except Exception as e:
        logger.error(f"Error setting provisioned concurrency: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": str(e)
        }), 500



@app.route('/2019-09-25/functions/<function_name>/event-invoke-config', methods=['GET'], strict_slashes=False)
def get_function_event_invoke_config_endpoint(function_name):
    """Get function event invoke configuration"""
    try:
        logger.info(f"Getting event invoke config for: {function_name}")

        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Function not found: {function_name}'
            }), 404

        # Return stored config or defaults
        qualifier = request.args.get('Qualifier', '$LATEST')
        config = {
            'FunctionArn': function_config.get('FunctionArn'),
            'MaximumRetryAttempts': function_config.get('MaximumRetryAttempts', 0),
            'MaximumEventAgeInSeconds': function_config.get('MaximumEventAgeInSeconds', 3600),
            'Qualifier': qualifier
        }

        return jsonify(config), 200

    except Exception as e:
        logger.error(f"Error getting event invoke config: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500


@app.route('/2019-09-25/functions/<function_name>/event-invoke-config', methods=['PUT'], strict_slashes=False)
def put_function_event_invoke_config_endpoint(function_name):
    """Create or update event invoke configuration"""
    try:
        logger.info(f"Setting event invoke config for: {function_name}")

        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Function not found: {function_name}'
            }), 404

        data = request.get_json() or {}
        qualifier = request.args.get('Qualifier', '$LATEST')

        function_config['MaximumRetryAttempts'] = data.get('MaximumRetryAttempts', 0)
        function_config['MaximumEventAgeInSeconds'] = data.get('MaximumEventAgeInSeconds', 3600)
        function_config['DestinationConfig'] = data.get('DestinationConfig', {})

        lifecycle_manager.db.save_function_to_db(function_config)

        config = {
            'FunctionArn': function_config.get('FunctionArn'),
            'MaximumRetryAttempts': function_config['MaximumRetryAttempts'],
            'MaximumEventAgeInSeconds': function_config['MaximumEventAgeInSeconds'],
            'DestinationConfig': function_config.get('DestinationConfig'),
            'Qualifier': qualifier
        }

        return jsonify(config), 200

    except ValueError as e:
        return jsonify({
            '__type': 'InvalidParameterValueException',
            'message': str(e)
        }), 400
    except Exception as e:
        logger.error(f"Error putting event invoke config: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500


@app.route('/2019-09-25/functions/<function_name>/event-invoke-config', methods=['POST'], strict_slashes=False)
def update_function_event_invoke_config_endpoint(function_name):
    """Update event invoke configuration"""
    try:
        logger.info(f"Updating event invoke config for: {function_name}")

        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Function not found: {function_name}'
            }), 404

        data = request.get_json() or {}
        qualifier = request.args.get('Qualifier', '$LATEST')

        if 'MaximumRetryAttempts' in data:
            function_config['MaximumRetryAttempts'] = data['MaximumRetryAttempts']
        if 'MaximumEventAgeInSeconds' in data:
            function_config['MaximumEventAgeInSeconds'] = data['MaximumEventAgeInSeconds']
        if 'DestinationConfig' in data:
            function_config['DestinationConfig'] = data['DestinationConfig']

        lifecycle_manager.db.save_function_to_db(function_config)

        config = {
            'FunctionArn': function_config.get('FunctionArn'),
            'MaximumRetryAttempts': function_config.get('MaximumRetryAttempts', 0),
            'MaximumEventAgeInSeconds': function_config.get('MaximumEventAgeInSeconds', 3600),
            'DestinationConfig': function_config.get('DestinationConfig', {}),
            'Qualifier': qualifier
        }

        return jsonify(config), 200

    except ValueError as e:
        return jsonify({
            '__type': 'InvalidParameterValueException',
            'message': str(e)
        }), 400
    except Exception as e:
        logger.error(f"Error updating event invoke config: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500


@app.route('/2019-09-25/functions/<function_name>/event-invoke-config', methods=['DELETE'], strict_slashes=False)
def delete_function_event_invoke_config_endpoint(function_name):
    """Delete event invoke configuration"""
    try:
        logger.info(f"Deleting event invoke config for: {function_name}")

        function_config = lifecycle_manager.db.get_function_from_db(function_name)
        if not function_config:
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Function not found: {function_name}'
            }), 404

        qualifier = request.args.get('Qualifier', '$LATEST')

        # Clear event invoke config
        function_config['MaximumRetryAttempts'] = None
        function_config['MaximumEventAgeInSeconds'] = None
        function_config['DestinationConfig'] = None

        lifecycle_manager.db.save_function_to_db(function_config)

        return '', 204

    except Exception as e:
        logger.error(f"Error deleting event invoke config: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500


@app.route('/2015-03-31/functions', methods=['POST'], strict_slashes=False)
def create_function():
    """Create a new Lambda function with multi-runtime support"""
    try:
        data = request.get_json()
        function_name = data.get('FunctionName')

        if not function_name:
            logger.error(f"InvalidParameterValueException: FunctionName is required")
            return jsonify({
                'errorMessage': 'FunctionName is required',
                'errorType': 'InvalidParameterValueException'
            }), 400

        # Check if function already exists
        existing_function = lifecycle_manager.db.get_function_from_db(function_name)
        if existing_function:
            logger.error(f"ResourceConflictException: Function already exists: {function_name}")
            error_response = {
                "__type": "ResourceConflictException:",
                "message": f'Function already exists: {function_name}'
            }
            return error_response, 409

        runtime = data.get('Runtime', 'python3.11')
        handler = data.get('Handler', 'lambda_function.handler')
        role = data.get('Role', f'arn:aws:iam::{ACCOUNT_ID}:role/lambda-role')
        environment = data.get('Environment', {}).get('Variables', {})

        # Get image config if present
        image_config = data.get('ImageConfig', {})
        command = image_config.get('Command')
        entrypoint = image_config.get('EntryPoint')
        workdir = image_config.get('WorkingDirectory')

        logging_config = data.get('LoggingConfig', {
            'LogFormat': 'Text',
            'ApplicationLogLevel': 'INFO',
            'SystemLogLevel': 'INFO',
            'LogGroup': f'/aws/lambda/{function_name}'
        })

        # Extract the custom log group name (if provided)
        # log_group_name = logging_config.get('LogGroup', f'/aws/lambda/{function_name}')
        # ====================================================================

        # Validate runtime
        if runtime not in RUNTIME_BASE_IMAGES and not runtime.startswith('provided'):
            logger.error(f"InvalidParameterValueException: Unsupported runtime: {runtime}")
            return jsonify({
                'errorMessage': f'Unsupported runtime: {runtime}',
                'errorType': 'InvalidParameterValueException'
            }), 400

        code = data.get('Code', {})
        image_uri = code.get('ImageUri')
        zip_file = code.get('ZipFile')

        logger.debug(f"Params: {data}")
        logger.debug(f"Environment variables: {list(environment.keys())}")
        logger.info(f"Creating Function: {function_name} with Runtime: {runtime}")

        if image_uri:
            # Verify/pull the image
            logger.info(f"Creating function from image: {image_uri}")
            built_image, err_resp, err_code = lifecycle_manager.build_function_image(
                function_name,
                runtime=runtime,
                image_uri=image_uri,
                handler=handler
            )
            if err_resp:
                return jsonify(err_resp), err_code

        elif zip_file:
            # Create from ZIP file (base64 encoded)
            logger.info(f"Creating function from ZIP file")

            # Decode ZIP file
            zip_data = base64.b64decode(zip_file)
            filename_hash = sha256(zip_file.encode('utf-8')).hexdigest()

            function_dir = FUNCTIONS_DIR / filename_hash
            function_dir.mkdir(exist_ok=True)

            # Extract ZIP
            zip_path = function_dir / 'function.zip'
            try:
                os.remove(zip_path)
            except:
                pass
            zip_path.write_bytes(zip_data)
            # TODO Feel like this should be a subdir of ./src, the image ends up with the zip, source and dockerfile otherwise.
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(function_dir)

            # Build the image (but don't start container)
            built_image, err_resp, err_code = lifecycle_manager.build_function_image(
                function_name,
                runtime=runtime,
                function_path=function_dir,
                handler=handler
            )
            if err_resp:
                return err_resp, err_code
        else:
            logger.error(f"InvalidParameterValueException: Either ImageUri or ZipFile must be provided in Code")
            return jsonify({
                'errorMessage': 'Either ImageUri or ZipFile must be provided in Code',
                'errorType': 'InvalidParameterValueException'
            }), 400

        # Create function configuration
        function_config = {
            'FunctionName': function_name,
            'FunctionArn': f'arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:{function_name}',
            'Runtime': runtime,
            'Handler': handler,
            'Role': role,
            'CodeSize': 0,
            'State': 'Active',
            'LastUpdateStatus': 'Successful',
            'PackageType': 'Image' if image_uri else 'Zip',
            'ImageUri': image_uri if image_uri else built_image,
            'CodeSha256': base64.b64encode((image_uri or built_image).encode()).decode(),
            'Environment': environment,
            'LoggingConfig': logging_config
        }
        function_config['ImageConfig'] = {
            'Command': command,
            'EntryPoint': entrypoint,
            'WorkingDirectory': workdir
        }

        # Save to database
        lifecycle_manager.db.save_function_to_db(function_config)

        logger.info(f"Function created successfully: {function_name}")

        # Return config without internal fields
        response_config = function_config.copy()
        response_config.pop('Endpoint', None)
        response_config.pop('ContainerName', None)
        response_config.pop('HostPort', None)

        return jsonify(response_config), 201

    except Exception as e:
        exc_type, _, tb = sys.exc_info()
        filename = tb.tb_frame.f_code.co_filename
        line_no = tb.tb_lineno
        error_details = f"{exc_type.__name__}: {e} (File \"{filename}\", line {line_no})"
        logger.error(f"Unhandled exception: {error_details}", exc_info=True)
        error_response = {
            "__type": "ServiceException:",
            "message": f"Unhandled exception for function: {function_name} - {error_details}"
        }
        return error_response, 500


@app.route('/2018-06-01/runtime/invocation/next', methods=['GET'])
def runtime_next():
    """Lambda Runtime API - Container polls this for next invocation."""
    if not lifecycle_manager:
        return jsonify({'message': 'Lambda not initialized'}), 500

    client_ip = _get_client_ip()

    # Get container metadata with retry for race condition during startup
    container_meta = _get_container_with_retry(client_ip)
    if not container_meta:
        logger.warning(f"Runtime next: container not found for IP {client_ip}")
        return jsonify({'message': 'Container not registered'}), 404

    function_name = container_meta.function_name
    container_id = container_meta.container_id

    # Validate container is in correct state to receive work
    if container_meta.state not in [ContainerState.READY, ContainerState.STARTING]:
        logger.error(
            f"Invalid state for next request - IP:{client_ip} "
            f"Container:{C.MAGENTA}{container_id}{C.RESET} Function:{function_name} State:{container_meta.state}"
        )
        return '', 204

    # Transition to LEASED - container is now waiting for work
    lifecycle_manager.update_container_state(container_id, ContainerState.LEASED)
    logger.debug(f'Container {C.MAGENTA}{container_id}{C.RESET} transitioned to LEASED state')

    # Block until task arrives (or container is killed)
    task = _wait_for_task(client_ip, function_name)

    if task is None:
        # Container was killed while waiting - just drop connection
        try:
            # ensure it's cleaned up
            lifecycle_manager.unregister_container(container_id)
        except:
            pass
        logger.debug(f"Container {C.MAGENTA}{container_id}{C.RESET} no longer exists, dropping connection")
        return '', 410

    # We have a task - prepare invocation response
    request_id = task.get('request_id')
    event = task.get('event')

    # Set container
    lifecycle_manager.log_manager.set_active_request(container_id, request_id)

    # Write START line to CloudWatch
    _write_start_log(container_id, request_id)

    # Build response
    response = _build_invocation_response(event, request_id, function_name)

    # Final state transition to RUNNING (container is processing invocation)
    # Check one last time that container still exists
    container_meta = lifecycle_manager.get_container_metadata_by_ip(client_ip)
    if not container_meta:
        logger.warning(f'Container killed before RUNNING transition - requeueing task {request_id}')
        lifecycle_manager.set_invocation_queue(function_name, task)
        return '', 410

    lifecycle_manager.update_container_state(container_id, ContainerState.RUNNING)
    lifecycle_manager.mark_container_active(container_id)

    logger.info(
        f"Dispatched invocation - Container:{C.MAGENTA}{container_id}{C.RESET} "
        f"Function:{function_name} RequestID:{request_id}"
    )
    return response, 200


def _get_container_with_retry(client_ip, max_retries=10, delay=0.5):
    """Retry lookup to handle race condition during container startup."""
    for retry in range(max_retries):
        container_meta = lifecycle_manager.get_container_metadata_by_ip(client_ip)
        if container_meta:
            return container_meta
        if retry < max_retries - 1:
            time.sleep(delay)
    return None


def _wait_for_task(client_ip, function_name):
    """
    Block waiting for a task from queue.
    Periodically checks if container still exists.
    Returns task dict or None if container was killed.
    """
    poll_interval = 0.1  # Check container state every 100ms

    while True:
        # Check if container still exists and is in LEASED state
        container_meta = lifecycle_manager.get_container_metadata_by_ip(client_ip)
        if not container_meta:
            logger.warning(f'Container killed while waiting for task - dropping connection')
            return None

        if container_meta.state != ContainerState.LEASED:
            logger.warning(f'Container state changed while waiting - State: {container_meta.state}')
            return None

        # Try to get a task (non-blocking)
        try:
            task = lifecycle_manager.get_invocation_queue_task(function_name, timeout=poll_interval)

            # Got a task - verify container still in correct state before returning
            container_meta = lifecycle_manager.get_container_metadata_by_ip(client_ip)
            if not container_meta or container_meta.state != ContainerState.LEASED:
                # Container killed or state changed - requeue task
                logger.warning(f'Container state changed after receiving task - requeueing')
                lifecycle_manager.set_invocation_queue(function_name, task)
                return None

            return task

        except Empty:
            # No task yet - loop continues to check again
            continue

        except Exception as e:
            # Unexpected error - log and return None
            logger.error(f"Error waiting for task on {function_name}: {e}", exc_info=True)
            return None


def _write_start_log(container_id, request_id):
    """Write START line to CloudWatch logs."""
    log_config = lifecycle_manager.log_manager.container_log_config.get(container_id, {})
    log_group = log_config.get('log_group')
    log_stream = log_config.get('log_stream')

    if log_group and log_stream:
        lifecycle_manager.log_manager.write_start_line(request_id, log_group, log_stream)
        logger.debug(f"Wrote START line for {request_id} to {log_group}/{log_stream}")


def _build_invocation_response(event, request_id, function_name):
    """Build Lambda Runtime API response with event payload and headers."""
    # Serialize event body
    if isinstance(event, (dict, list)):
        body = json.dumps(event)
        mimetype = 'application/json'
    else:
        body = '' if event is None else str(event)
        mimetype = 'text/plain'

    response = Response(body, mimetype=mimetype)

    # Add required Lambda Runtime API headers
    response.headers['lambda-runtime-aws-request-id'] = request_id
    response.headers['lambda-runtime-invoked-function-arn'] = (
        f'arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:{function_name}'
    )
    response.headers['lambda-runtime-deadline-ms'] = str(int(time.time() * 1000) + 60000)

    return response

@app.route('/2018-06-01/runtime/invocation/<request_id>/response', methods=['POST'])
def runtime_response(request_id):
    """Container posts back successful invocation response."""
    if not lifecycle_manager:
        return jsonify({'message': 'Lifecycle not initialized'}), 500

    client_ip = _get_client_ip()
    metadata = lifecycle_manager.get_container_metadata_by_ip(client_ip)
    container_id = metadata.container_id if metadata else None

    # After marking invocation complete
    lifecycle_manager.log_manager.clear_active_request(container_id)

    logger.info(f"Response from ClientIP:{client_ip} ContainerID:{C.MAGENTA}{container_id}{C.RESET} for RequestId:{C.CYAN}{request_id}{C.RESET}")

    # Read response body
    payload = request.get_data() or b''
    try:
        resp_body = json.loads(payload.decode()) if payload else None
    except Exception:
        resp_body = payload.decode(errors='ignore')

    try:
        lifecycle_manager.mark_invocation_complete(request_id, resp_body)

        # Mark container active, warm, and ready for next invocation
        if container_id:
            lifecycle_manager.mark_container_active(container_id)
            meta = lifecycle_manager.get_container_metadata(container_id)
            if meta:
                meta.mark_warm()
                # Transition back to READY - invocation complete, will poll for next
                # Update last_activity when transitioning from RUNNING to READY (idle timer starts)
                if meta.state == ContainerState.RUNNING:
                    meta.update_last_activity(lifecycle_manager)
                lifecycle_manager.update_container_state(container_id, ContainerState.READY)

        return ('', 202)
    except Exception as e:
        logger.error(f"Error processing runtime response: {e}")
        return jsonify({'message': str(e)}), 500

@app.route('/2018-06-01/runtime/init/error', methods=['POST'])
def runtime_error():
    error_data = request.get_data()
    logger.error(f"INIT Error: {error_data}")
    return ('', 202)

@app.route('/2018-06-01/runtime/invocation/<request_id>/error', methods=['POST'])
def runtime_request_error(request_id):
    """Container posts back invocation error."""
    if not lifecycle_manager:
        return jsonify({'message': 'Lifecycle not initialized'}), 500

    client_ip = _get_client_ip()
    metadata = lifecycle_manager.get_container_metadata_by_ip(client_ip)
    container_id = metadata.container_id if metadata else None

    # After marking invocation complete
    lifecycle_manager.log_manager.clear_active_request(container_id)

    logger.warning(f"Error response from ClientIP:{client_ip} ContainerID:{C.MAGENTA}{container_id}{C.RESET} for RequestId:{C.CYAN}{request_id}{C.RESET}")

    payload = request.get_data() or b''
    try:
        error_data = json.loads(payload.decode()) if payload else None
    except Exception:
        error_data = payload.decode(errors='ignore')

    try:
        lifecycle_manager.mark_invocation_error(request_id, error_data)

        # Container handled error, transition back to READY
        if container_id:
            meta = lifecycle_manager.get_container_metadata(container_id)
            if meta:
                # Update last_activity when transitioning from RUNNING to READY (idle timer starts)
                if meta.state == ContainerState.RUNNING:
                    meta.update_last_activity(lifecycle_manager)
                lifecycle_manager.update_container_state(container_id, ContainerState.READY)

        return ('', 202)
    except Exception as e:
        logger.error(f"Error processing runtime error: {e}")
        return jsonify({'message': str(e)}), 500


@app.route('/health', methods=['GET'])
def healthcheck():
    """Healthcheck"""
    if not lifecycle_manager:
        return jsonify({'error': 'Lifecycle manager not initialized'}), 500

    status = lifecycle_manager.get_status()

    # Add log manager status
    if log_manager:
        status['log_manager'] = {
            'running': log_manager.running,
            'active_containers': list[str](container for container in lifecycle_manager.container_activity) if hasattr(lifecycle_manager, 'container_activity') else []
        }

    return jsonify(status), 200

@app.route('/debug/lambda-status', methods=['GET'])
def lambda_debug_status():
    """Debug endpoint to check lambda lifecycle status"""
    if not lifecycle_manager:
        return jsonify({'error': 'Lifecycle manager not initialized'}), 500

    status = lifecycle_manager.get_status()

    # Add log manager status
    if log_manager:
        status['log_manager'] = {
            'running': log_manager.running,
            'active_containers': list(lifecycle_manager.container_metadata)
        }

    return jsonify(status), 200

##
## Temp Cloudwatch logging handled here due to lambda using it the most.
## move to it's own service with cloudwatch later
##

def create_log_group():
    """Create a CloudWatch log group"""
    data = request.get_json(force=True)
    group = data.get('logGroupName')

    if not group:
        return jsonify({
            '__type': 'InvalidParameterException',
            'message': 'logGroupName is required'
        }), 400

    try:
        created = log_manager.logs_db.create_log_group(group)
        if not created:
            return jsonify({
                '__type': 'ResourceAlreadyExistsException',
                'message': f'Log group {group} already exists'
            }), 400

        logger.info(f"Created log group: {group}")
        return jsonify({}), 200
    except Exception as e:
        logger.error(f"Error creating log group: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500

def create_log_stream():
    """Create a CloudWatch log stream"""
    data = request.get_json(force=True)
    group = data.get('logGroupName')
    stream = data.get('logStreamName')

    if not group or not stream:
        return jsonify({
            '__type': 'InvalidParameterException',
            'message': 'logGroupName and logStreamName are required'
        }), 400

    try:
        if not log_manager.logs_db.log_group_exists(group):
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Log group {group} does not exist'
            }), 404

        created = log_manager.logs_db.create_log_stream(group, stream)
        if not created:
            return jsonify({
                '__type': 'ResourceAlreadyExistsException',
                'message': f'Log stream {stream} already exists'
            }), 400

        logger.info(f"Created log stream: {group}/{stream}")
        return jsonify({}), 200
    except Exception as e:
        logger.error(f"Error creating log stream: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500

def put_log_events():
    """Put log events to a stream"""
    data = request.get_json(force=True)
    group = data.get('logGroupName')
    stream = data.get('logStreamName')
    events = data.get('logEvents', [])

    if not group or not stream:
        return jsonify({
            '__type': 'InvalidParameterException',
            'message': 'logGroupName and logStreamName are required'
        }), 400

    try:
        if not log_manager.logs_db.log_group_exists(group):
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Log group {group} does not exist'
            }), 404

        if not log_manager.logs_db.log_stream_exists(group, stream):
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Log stream {stream} does not exist'
            }), 404

        next_seq_token = log_manager.logs_db.put_log_events(group, stream, events)
        return jsonify({"nextSequenceToken": next_seq_token}), 200
    except Exception as e:
        logger.error(f"Error putting log events: {e}", exc_info=True)
        return jsonify({
            '__type': 'ServiceUnavailableException',
            'message': str(e)
        }), 500

def get_log_events():
    """Get log events from a stream (for AWS CLI)"""
    data = request.get_json(force=True)
    group = data.get('logGroupName')
    stream = data.get('logStreamName')
    start_time = data.get('startTime')
    end_time = data.get('endTime')
    limit = data.get('limit', 10000)
    start_from_head = data.get('startFromHead', True)
    next_token = data.get('nextToken')

    if not group or not stream:
        return jsonify({
            '__type': 'InvalidParameterException',
            'message': 'logGroupName and logStreamName are required'
        }), 400

    try:
        if not log_manager.logs_db.log_group_exists(group):
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Log group {group} does not exist'
            }), 404

        if not log_manager.logs_db.log_stream_exists(group, stream):
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Log stream {stream} does not exist'
            }), 404

        # Get events from database
        events = log_manager.logs_db.get_log_events(
            group, stream, start_time, end_time, limit, start_from_head
        )

        # Format response for AWS CLI
        return jsonify({
            'events': events,
            'nextForwardToken': 'f/00000000000000000000000000000000000000000000000000000000',
            'nextBackwardToken': 'b/00000000000000000000000000000000000000000000000000000000'
        }), 200
    except Exception as e:
        logger.error(f"Error getting log events: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500

def describe_log_groups():
    """List all log groups"""
    data = request.get_json(force=True) or {}
    prefix = data.get('logGroupNamePrefix', '')
    limit = data.get('limit', 50)

    try:
        groups = log_manager.logs_db.list_log_groups(prefix if prefix else None, limit)

        # Format for AWS response (add ARNs)
        formatted_groups = []
        for group in groups:
            formatted_groups.append({
                'logGroupName': group['logGroupName'],
                'creationTime': group['creationTime'],
                'metricFilterCount': group['metricFilterCount'],
                'arn': f'arn:aws:logs:{REGION}:{ACCOUNT_ID}:log-group:{group["logGroupName"]}',
                'storedBytes': group['storedBytes']
            })
            if group.get('retentionInDays'):
                formatted_groups[-1]['retentionInDays'] = group['retentionInDays']

        return jsonify({'logGroups': formatted_groups}), 200
    except Exception as e:
        logger.error(f"Error describing log groups: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500

def describe_log_streams():
    """List streams in a log group"""
    data = request.get_json(force=True)
    group_name = data.get('logGroupName')
    prefix = data.get('logStreamNamePrefix', '')
    limit = data.get('limit', 50)
    order_by = data.get('orderBy', 'LogStreamName')

    if not group_name:
        return jsonify({
            '__type': 'InvalidParameterException',
            'message': 'logGroupName is required'
        }), 400

    try:
        if not log_manager.logs_db.log_group_exists(group_name):
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Log group {group_name} does not exist'
            }), 404

        streams = log_manager.logs_db.list_log_streams(
            group_name, prefix if prefix else None, limit, order_by
        )

        # Format for AWS response (add ARNs)
        formatted_streams = []
        for stream in streams:
            formatted_stream = {
                'logStreamName': stream['logStreamName'],
                'creationTime': stream['creationTime'],
                'arn': f'arn:aws:logs:{REGION}:{ACCOUNT_ID}:log-group:{group_name}:log-stream:{stream["logStreamName"]}',
                'storedBytes': stream['storedBytes']
            }
            if stream.get('firstEventTimestamp'):
                formatted_stream['firstEventTimestamp'] = stream['firstEventTimestamp']
            if stream.get('lastEventTimestamp'):
                formatted_stream['lastEventTimestamp'] = stream['lastEventTimestamp']
            if stream.get('lastIngestionTime'):
                formatted_stream['lastIngestionTime'] = stream['lastIngestionTime']

            formatted_streams.append(formatted_stream)

        return jsonify({'logStreams': formatted_streams}), 200
    except Exception as e:
        logger.error(f"Error describing log streams: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500

def get_log_events_api():
    """Get log events from a stream"""
    data = request.get_json(force=True)
    group_name = data.get('logGroupName')
    stream_name = data.get('logStreamName')
    start_time = data.get('startTime')
    end_time = data.get('endTime')
    limit = data.get('limit', 10000)
    start_from_head = data.get('startFromHead', True)

    if not group_name or not stream_name:
        return jsonify({
            '__type': 'InvalidParameterException',
            'message': 'logGroupName and logStreamName are required'
        }), 400

    try:
        if not log_manager.logs_db.log_group_exists(group_name):
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Log group {group_name} not found'
            }), 404

        if not log_manager.logs_db.log_stream_exists(group_name, stream_name):
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Log stream {stream_name} not found'
            }), 404

        events = log_manager.logs_db.get_log_events(
            group_name, stream_name, start_time, end_time, limit, start_from_head
        )

        return jsonify({
            'events': events,
            'nextForwardToken': 'f/00000000000000000000000000000000000000000000000000000000',
            'nextBackwardToken': 'b/00000000000000000000000000000000000000000000000000000000'
        }), 200
    except Exception as e:
        logger.error(f"Error getting log events: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500

def filter_log_events():
    """Filter log events across streams"""
    data = request.get_json(force=True)
    group_name = data.get('logGroupName')
    stream_names = data.get('logStreamNames', [])
    filter_pattern = data.get('filterPattern', '')
    start_time = data.get('startTime')
    end_time = data.get('endTime')
    limit = data.get('limit', 10000)

    if not group_name:
        return jsonify({
            '__type': 'InvalidParameterException',
            'message': 'logGroupName is required'
        }), 400

    try:
        if not log_manager.logs_db.log_group_exists(group_name):
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Log group {group_name} does not exist'
            }), 404

        events = log_manager.logs_db.filter_log_events(
            group_name,
            stream_names if stream_names else None,
            start_time,
            end_time,
            filter_pattern if filter_pattern else None,
            limit
        )

        # Get list of searched streams
        if stream_names:
            searched_streams = stream_names
        else:
            # Get all streams in the log group
            streams = log_manager.logs_db.list_log_streams(group_name, limit=1000)
            searched_streams = [s['logStreamName'] for s in streams]

        return jsonify({
            'events': events,
            'searchedLogStreams': [
                {'logStreamName': s, 'searchedCompletely': True}
                for s in searched_streams
            ]
        }), 200
    except Exception as e:
        logger.error(f"Error filtering log events: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500

def delete_log_group():
    """Delete a log group"""
    data = request.get_json(force=True)
    group_name = data.get('logGroupName')

    if not group_name:
        return jsonify({
            '__type': 'InvalidParameterException',
            'message': 'logGroupName is required'
        }), 400

    try:
        if not log_manager.logs_db.log_group_exists(group_name):
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Log group {group_name} does not exist'
            }), 404

        deleted = log_manager.logs_db.delete_log_group(group_name)

        if deleted:
            logger.info(f"Deleted log group {group_name}")
            return jsonify({}), 200
        else:
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Log group {group_name} does not exist'
            }), 404
    except Exception as e:
        logger.error(f"Error deleting log group: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500

def delete_log_stream():
    """Delete a log stream"""
    data = request.get_json(force=True)
    group_name = data.get('logGroupName')
    stream_name = data.get('logStreamName')

    if not group_name or not stream_name:
        return jsonify({
            '__type': 'InvalidParameterException',
            'message': 'logGroupName and logStreamName are required'
        }), 400

    try:
        if not log_manager.logs_db.log_group_exists(group_name):
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Log group {group_name} does not exist'
            }), 404

        if not log_manager.logs_db.log_stream_exists(group_name, stream_name):
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Log stream {stream_name} does not exist'
            }), 404

        deleted = log_manager.logs_db.delete_log_stream(group_name, stream_name)

        if deleted:
            logger.info(f"Deleted log stream {group_name}/{stream_name}")
            return jsonify({}), 200
        else:
            return jsonify({
                '__type': 'ResourceNotFoundException',
                'message': f'Log stream {stream_name} does not exist'
            }), 404
    except Exception as e:
        logger.error(f"Error deleting log stream: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500

# CloudWatch Logs API endpoint
# ============================================================================
@app.route('/logs', methods=['POST'])
def cloudwatch_logs_api():
    """
    CloudWatch Logs API endpoint
    Uses X-Amz-Target header to determine operation
    """
    target = request.headers.get('X-Amz-Target', '')

    if target.endswith('CreateLogGroup'):
        return create_log_group()
    elif target.endswith('CreateLogStream'):
        return create_log_stream()
    elif target.endswith('PutLogEvents'):
        return put_log_events()
    elif target.endswith('GetLogEvents'):
        return get_log_events_api()
    elif target.endswith('DescribeLogGroups'):
        return describe_log_groups()
    elif target.endswith('DescribeLogStreams'):
        return describe_log_streams()
    elif target.endswith('FilterLogEvents'):
        return filter_log_events()
    elif target.endswith('DeleteLogGroup'):
        return delete_log_group()
    elif target.endswith('DeleteLogStream'):
        return delete_log_stream()
    else:
        return jsonify({
            "__type": "UnknownOperationException",
            "message": f"Unsupported target {target}"
        }), 400


# Also add a catch-all to see what URLs are being hit
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def catch_all(path):
    """Catch-all route for debugging"""
    logger.warning(f"Unhandled route: {request.method} /{path}")
    logger.warning(f"Query params: {vars(request.args)}")
    logger.warning(f"Available routes: {[str(rule) for rule in app.url_map.iter_rules()]}")
    return jsonify({
        'errorMessage': f'Route not found: {request.method} /{path}',
        'errorType': 'RouteNotFoundException',
        'availableRoutes': [str(rule) for rule in app.url_map.iter_rules()]
    }), 404


# CloudWatch Logs API endpoint - temporary since lambda uses it the most
# ============================================================================


if __name__ == '__main__':

    # Initialize Docker client and lifecycle manager singleton
    try:
        docker_client = docker.from_env()
    except Exception:
        raise Exception("Failed initialize Docker client")

    # Cloudwatch Logs - though proxied in Lambda for now....
    log_manager = LogManager(docker_client)
    log_manager.start()

    lifecycle_manager = ContainerLifecycleManager(docker_client)

    try:
        # lifecycle_manager.recover_existing_containers()
        lifecycle_manager.start()
    except Exception as e:
        logger.error(f"Error during lifecycle bootstrap: {e}")


    logger.info('Starting LocalCloud Lambda emulation HTTP API (Flask) on 0.0.0.0:4566')
    app.run(host='0.0.0.0', port=4566)
