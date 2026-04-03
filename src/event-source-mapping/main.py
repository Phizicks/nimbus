"""
Lambda Event Source Mapping - Polls SQS and invokes Lambda functions
"""

import threading
import time
import os
import sqlite3
import json
import uuid
import requests
import boto3
import botocore
import datetime
from typing import Dict, List, Optional, Set
from contextlib import contextmanager
from collections import defaultdict
from enum import Enum
from timedlocking import TimedLock
from flask import Flask, request, jsonify
import logging

logger = logging.getLogger(__name__)

API_BASE = os.getenv("AWS_ENDPOINT_URL", "http://api:4566")

DB_PATH = os.getenv("STORAGE_PATH", "/data") + "/event_source_mappings.db"

# Helper to create QueueManager and EventSourceMapping singletons
_queue_manager = None
_esm_service = None


class DuplicateMappingError(Exception):
    """Raised when attempting to create a mapping that already exists"""

    def __init__(self, mapping: Dict):
        super().__init__(f"Mapping already exists: {mapping.get('UUID')}")
        self.mapping = mapping


class InvocationState(Enum):
    """States for tracking invocation lifecycle"""

    QUEUED = "queued"
    DISPATCHED = "dispatched"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class EMSDatabase:
    """Database layer for Event Source Mappings - UNCHANGED"""

    def __init__(self, db_path: str):
        self.db_path = DB_PATH
        self._init_database()

    def _init_database(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS event_source_mappings (
                    uuid TEXT PRIMARY KEY,
                    event_source_arn TEXT NOT NULL,
                    function_arn TEXT NOT NULL,
                    function_name TEXT NOT NULL,
                    queue_name TEXT NOT NULL,
                    batch_size INTEGER NOT NULL DEFAULT 10,
                    state TEXT NOT NULL DEFAULT 'Enabled',
                    state_transition_reason TEXT,
                    last_modified REAL NOT NULL,
                    created_at REAL NOT NULL,
                    table_name TEXT,
                    stream_id TEXT,
                    source_type TEXT,
                    UNIQUE(queue_name, function_name)
                )
            """
            )

            # Add columns if upgrading existing database
            try:
                cursor.execute(
                    "ALTER TABLE event_source_mappings ADD COLUMN table_name TEXT"
                )
            except sqlite3.OperationalError:
                logger.debug("table_name column already exists")

            try:
                cursor.execute(
                    "ALTER TABLE event_source_mappings ADD COLUMN stream_id TEXT"
                )
            except sqlite3.OperationalError:
                logger.debug("stream_id column already exists")

            try:
                cursor.execute(
                    "ALTER TABLE event_source_mappings ADD COLUMN source_type TEXT"
                )
            except sqlite3.OperationalError:
                logger.debug("source_type column already exists")

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_function_name
                ON event_source_mappings(function_name)
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_state
                ON event_source_mappings(state)
            """
            )

            conn.commit()
            logger.info("EMS Database initialized at %s", self.db_path)

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            logger.error("Database error: %s", e, exc_info=True)
            raise
        finally:
            conn.close()

    def create_mapping(self, mapping: Dict) -> bool:
        """Insert a new event source mapping"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO event_source_mappings (
                        uuid, event_source_arn, function_arn, function_name,
                        queue_name, batch_size, state, state_transition_reason,
                        last_modified, created_at, table_name, stream_id, source_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        mapping["UUID"],
                        mapping["EventSourceArn"],
                        mapping["FunctionArn"],
                        mapping["FunctionName"],
                        mapping["QueueName"],
                        mapping["BatchSize"],
                        mapping["State"],
                        mapping["StateTransitionReason"],
                        mapping["LastModified"],
                        time.time(),
                        mapping.get("TableName"),
                        mapping.get("StreamId"),
                        mapping.get("SourceType", "NotSet"),
                    ),
                )
                conn.commit()
                logger.info("Created mapping in DB: %s", mapping['UUID'])
                return True
        except Exception as e:
            logger.error("Error creating mapping: %s", e, exc_info=True)
            return False

    def get_mapping_by_uuid(self, uuid: str) -> Optional[Dict]:
        """Get a single mapping by UUID"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT * FROM event_source_mappings WHERE uuid = ?
                """,
                    (uuid,),
                )
                row = cursor.fetchone()
                if row:
                    return self._row_to_dict(row)
                return None
        except Exception as e:
            logger.error("Error getting mapping: %s", e, exc_info=True)
            return None

    def get_mapping_by_function_name(self, function_name: str) -> Optional[Dict]:
        """Get a single mapping by function name"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT * FROM event_source_mappings WHERE function_name = ?
                """,
                    (function_name,),
                )
                row = cursor.fetchone()
                if row:
                    return self._row_to_dict(row)
                return None
        except Exception as e:
            logger.error("Error getting mapping: %s", e, exc_info=True)
            return None

    def get_all_mappings(self, function_name: str = "") -> List[Dict]:
        """Get all event source mappings"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                query = """SELECT * FROM event_source_mappings"""
                params = []

                if function_name:
                    query += " WHERE function_name = ?"
                    params.append(function_name)

                query += " ORDER BY last_modified DESC"

                cursor.execute(query, params)
                rows = cursor.fetchall()

                return [self._row_to_dict(row) for row in rows]
        except Exception as e:
            logger.error("Error getting mappings: %s", e, exc_info=True)
            return []

    def get_enabled_mappings(self) -> List[Dict]:
        """Get all enabled mappings"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT * FROM event_source_mappings
                    WHERE state = 'Enabled'
                    ORDER BY created_at ASC
                """
                )
                rows = cursor.fetchall()

                return [self._row_to_dict(row) for row in rows]
        except Exception as e:
            logger.error("Error getting enabled mappings: %s", e, exc_info=True)
            return []

    def update_mapping(self, uuid: str, updates: Dict) -> bool:
        """Update an existing mapping"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                set_clauses = []
                values = []

                for key, value in updates.items():
                    db_key = self._camel_to_snake(key)
                    set_clauses.append(f"{db_key} = ?")
                    values.append(value)

                if not set_clauses:
                    logger.warning("No updates to apply for mapping: %s", uuid)
                    return False

                set_clauses.append("last_modified = ?")
                values.append(time.time())
                values.append(uuid)

                # Build parameterized query safely to avoid SQL injection
                # Column names are validated via _camel_to_snake(), values are parameterized
                set_clause_str = ', '.join(set_clauses)
                query = f"UPDATE event_source_mappings SET {set_clause_str} WHERE uuid = ?"  # nosec

                cursor.execute(query, values)
                conn.commit()

                if cursor.rowcount > 0:
                    logger.info("Updated mapping: %s", uuid)
                    return True
                else:
                    logger.warning("No mapping found to update: %s", uuid)
                    return False
        except Exception as e:
            logger.error("Error updating mapping: %s", e, exc_info=True)
            return False

    def delete_mapping(self, uuid: str) -> bool:
        """Delete a mapping"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    DELETE FROM event_source_mappings WHERE uuid = ?
                """,
                    (uuid,),
                )
                conn.commit()

                if cursor.rowcount > 0:
                    logger.info("Deleted mapping: %s", uuid)
                    return True
                else:
                    logger.warning("No mapping found to delete: %s", uuid)
                    return False
        except Exception as e:
            logger.error("Error deleting mapping: %s", e, exc_info=True)
            return False

    def mapping_exists(self, uuid: str) -> bool:
        """Check if a mapping exists"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT 1 FROM event_source_mappings WHERE uuid = ? LIMIT 1
                """,
                    (uuid,),
                )
                return cursor.fetchone() is not None
        except Exception as e:
            logger.error("Error checking mapping existence: %s", e, exc_info=True)
            return False

    def get_mapping_by_queue_and_function(
        self, queue_name: str, function_name: str
    ) -> Optional[Dict]:
        """Get a mapping by queue name and function name (used to detect duplicates)"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT * FROM event_source_mappings
                    WHERE queue_name = ? AND function_name = ? LIMIT 1
                """,
                    (queue_name, function_name),
                )
                row = cursor.fetchone()
                if row:
                    return self._row_to_dict(row)
                return None
        except Exception as e:
            logger.error("Error getting mapping by queue+function: %s", e, exc_info=True)
            return None

    def _row_to_dict(self, row: sqlite3.Row) -> Dict:
        """Convert database row to mapping dictionary"""
        return {
            "UUID": row["uuid"],
            "EventSourceArn": row["event_source_arn"],
            "FunctionArn": row["function_arn"],
            "FunctionName": row["function_name"],
            "QueueName": row["queue_name"],
            "BatchSize": row["batch_size"],
            "State": row["state"],
            "StateTransitionReason": row["state_transition_reason"],
            "LastModified": row["last_modified"],
            "TableName": row["table_name"],
            "StreamId": row["stream_id"],
            "SourceType": row["source_type"],  # if 'source_type' in row else 'UnSet'
        }

    def _camel_to_snake(self, name: str) -> str:
        """Convert camelCase to snake_case"""
        result = []
        for i, char in enumerate(name):
            if char.isupper() and i > 0:
                result.append("_")
            result.append(char.lower())
        return "".join(result)


class EventSourceMapping:
    """Manages event source mappings between SQS queues and Lambda functions"""

    def __init__(self, queue_manager, account_id, region):
        self.queue_manager = queue_manager
        self.account_id = account_id
        self.region = region

        self.startup_thread = None
        self.cleanup_thread = None

        # Initialize boto3 DynamoDB Streams client
        self.dynamodb_endpoint = os.getenv("DYNAMODB_ENDPOINT_URL", "http://ddb:8000")
        self.streams_db = None

        # Initialize database
        self.db = EMSDatabase(DB_PATH)

        # Polling threads
        self.polling_threads = {}
        self._thread_lock = TimedLock(warn_threshold=10)

        # Running flag
        self._running = False

        # Stats per mapping
        self.stats = defaultdict(
            lambda: {
                "messages_received": 0,
                "messages_processed": 0,
                "messages_failed": 0,
                "invocations": 0,
                "last_poll": None,
            }
        )

    def _to_aws_arn(self, stream_id: str, table_name: str) -> str:
        """Convert stream ID to AWS-compatible ARN format"""
        return f"arn:aws:dynamodb:{self.region}:{self.account_id}:table/{table_name}/stream/{stream_id}"

    def _from_aws_arn(self, aws_arn: str) -> str:
        """Extract stream ID from AWS ARN (for ScyllaDB API calls)"""
        if "/stream/" in aws_arn:
            return aws_arn.split("/stream/")[-1]
        # Already a stream ID
        return aws_arn

    def _find_table_for_stream(self, stream_id: str) -> Optional[str]:
        """Find which table a stream ID belongs to"""
        try:
            dynamodb = boto3.client(
                "dynamodb",
                region_name=self.region,
                endpoint_url=self.dynamodb_endpoint,
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "localcloud"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "localcloud"),
            )

            # List all tables
            response = dynamodb.list_tables()
            table_names = response.get("TableNames", [])

            logger.debug("Searching %s tables for stream %s", len(table_names), stream_id)

            # Check each table's stream
            for table_name in table_names:
                try:
                    table_response = dynamodb.describe_table(TableName=table_name)
                    table_stream_arn = table_response.get("Table", {}).get(
                        "LatestStreamArn"
                    )

                    if table_stream_arn == stream_id:
                        logger.info("Found matching table: %s", table_name)
                        return table_name

                except Exception as e:
                    logger.debug("Error checking table %s: %s", table_name, e)
                    continue

            logger.warning("No table found with stream ID: %s", stream_id)
            return None

        except Exception as e:
            logger.error("Error searching for stream table: %s", e, exc_info=True)
            return None

    # Faaaark this is annoying
    def _parse_event_source_arn(self, event_source_arn: str) -> Dict:
        """
        Parse event source ARN and extract relevant information

        Returns dict with:
        - source_type: 'sqs' or 'dynamodb' or (future implementations)
        - queue_name or table_name
        - stream_id (for DynamoDB)
        - normalized_arn (AWS-compatible format)
        """
        result = {
            "source_type": None,
            "queue_name": None,
            "table_name": None,
            "stream_id": None,
            "normalized_arn": event_source_arn,
            "original_arn": event_source_arn,
        }

        # SQS Queue - standard format
        if ":sqs:" in event_source_arn:
            result["source_type"] = "sqs"
            result["queue_name"] = event_source_arn.split(":")[-1]
            logger.debug("Parsed as SQS queue: %s", result['queue_name'])
            return result

        # DynamoDB Stream - AWS format
        elif ":dynamodb:" in event_source_arn and "/stream/" in event_source_arn:
            result["source_type"] = "dynamodb"
            parts = event_source_arn.split("/table/")[-1]
            result["table_name"] = parts.split("/stream/")[0]
            result["stream_id"] = parts.split("/stream/")[-1]
            logger.debug(
                f"Parsed as DynamoDB stream: table={result['table_name']}, stream={result['stream_id']}"
            )
            return result

        # ScyllaDB format: arn:scylla:alternator:alternator_test-table:scylla:table/test-table
        elif "scylla" in event_source_arn.lower():
            result["source_type"] = "dynamodb"

            # Extract table name from the end
            if "/table/" in event_source_arn:
                result["table_name"] = event_source_arn.split("/table/")[-1]
            elif ":table/" in event_source_arn:
                result["table_name"] = event_source_arn.split(":table/")[-1]

            # Query DynamoDB for stream ID
            if result["table_name"]:
                logger.info(
                    f"ScyllaDB ARN detected, querying for stream ID of table: {result['table_name']}"
                )
                result["stream_id"] = self._get_stream_id_from_table(
                    result["table_name"]
                )
                if result["stream_id"]:
                    result["normalized_arn"] = self._to_aws_arn(
                        result["stream_id"], result["table_name"]
                    )
                    logger.info("Normalized ARN: %s", result['normalized_arn'])
            return result

        # Bare stream ID: S78066be1-f911-11f0-8dd7-c100609dac5d
        # Must start with 'S', be longer than 30 chars, and contain hyphens (UUID pattern)
        elif (
            event_source_arn.startswith("S")
            and len(event_source_arn) > 30
            and event_source_arn.count("-") >= 4
        ):

            result["source_type"] = "dynamodb"
            result["stream_id"] = event_source_arn

            # Try to find table name by querying all tables
            logger.info(
                f"Bare stream ID detected: {event_source_arn}, searching for table..."
            )
            table_name = self._find_table_for_stream(event_source_arn)

            if table_name:
                result["table_name"] = table_name
                result["normalized_arn"] = self._to_aws_arn(
                    event_source_arn, table_name
                )
                logger.info("Found table %s for stream %s", table_name, event_source_arn)
            else:
                logger.error("Could not find table for stream ID: %s", event_source_arn)

            return result

        # Unknown format - assume SQS for backward compatibility
        # logger.warning("Unknown ARN format: %s, assuming SQS", event_source_arn)
        # result['source_type'] = 'sqs'
        result["queue_name"] = event_source_arn.split(":")[-1]
        logger.critical("-------------- Unknown event_source_arn --------------")
        return result

    def _get_stream_id_from_table(self, table_name: str) -> Optional[str]:
        """Query DynamoDB to get the stream ID for a table"""
        try:
            dynamodb = boto3.client(
                "dynamodb",
                region_name=self.region,
                endpoint_url=self.dynamodb_endpoint,
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "localcloud"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "localcloud"),
            )

            response = dynamodb.describe_table(TableName=table_name)
            stream_spec = response.get("Table", {}).get("StreamSpecification", {})

            if not stream_spec.get("StreamEnabled"):
                logger.warning("Table %s does not have streams enabled", table_name)
                return None

            stream_arn = response.get("Table", {}).get("LatestStreamArn")

            # ScyllaDB returns just the stream ID (UUID), not full ARN
            if stream_arn and not stream_arn.startswith("arn:"):
                return stream_arn

            # If it's a full ARN, extract the stream ID
            if stream_arn and "/stream/" in stream_arn:
                return stream_arn.split("/stream/")[-1]

            return stream_arn

        except Exception as e:
            logger.error(
                f"Error getting stream ID for table {table_name}: {e}", exc_info=True
            )
            return None

    def create_event_source_mapping(
        self,
        event_source_arn: str,
        function_name: str,
        batch_size: int = 10,
        enabled: bool = True,
    ) -> Dict:
        """Create a new event source mapping"""
        logger.info(
            f"Creating ESM: function={function_name}, arn={event_source_arn}, enabled={enabled}"
        )

        # Parse the ARN
        parsed = self._parse_event_source_arn(event_source_arn)

        if not parsed["source_type"]:
            raise ValueError(
                f"Could not determine source type from ARN: {event_source_arn}"
            )

        logger.info("Detected source type: %s", parsed['source_type'])

        mapping_uuid = str(uuid.uuid4())

        if parsed["source_type"] == "sqs":
            queue_name = parsed["queue_name"]
            mapping = {
                "UUID": mapping_uuid,
                "EventSourceArn": event_source_arn,
                "FunctionArn": f"arn:aws:lambda:{self.region}:{self.account_id}:function:{function_name}",
                "FunctionName": function_name,
                "QueueName": queue_name,
                "BatchSize": min(max(batch_size, 1), 10),
                "State": "Enabled" if enabled else "Disabled",
                "StateTransitionReason": "User action",
                "LastModified": time.time(),
                "SourceType": "sqs",
            }
            existing = self.db.get_mapping_by_queue_and_function(
                queue_name, function_name
            )

        else:  # DynamoDB
            table_name = parsed["table_name"]
            stream_id = parsed["stream_id"]

            if not table_name or not stream_id:
                raise ValueError(
                    f"DynamoDB stream mapping requires table name and stream ID. "
                    f"Got table={table_name}, stream={stream_id} from ARN: {event_source_arn}"
                )

            normalized_arn = parsed["normalized_arn"]

            mapping = {
                "UUID": mapping_uuid,
                "EventSourceArn": normalized_arn,
                "FunctionArn": f"arn:aws:lambda:{self.region}:{self.account_id}:function:{function_name}",
                "FunctionName": function_name,
                "QueueName": table_name,  # For unique constraint
                "TableName": table_name,
                "StreamId": stream_id,
                "BatchSize": min(max(batch_size, 1), 100),
                "State": "Enabled" if enabled else "Disabled",
                "StateTransitionReason": "User action",
                "LastModified": time.time(),
                "SourceType": "dynamodb",
            }
            existing = self.db.get_mapping_by_queue_and_function(
                table_name, function_name
            )

        if existing:
            logger.info("Mapping already exists: %s", existing['UUID'])
            raise DuplicateMappingError(existing)

        if not self.db.create_mapping(mapping):
            raise Exception("Failed to create mapping in database")

        logger.info("Created %s mapping %s", parsed['source_type'], mapping_uuid)

        if enabled:
            self._start_polling(mapping_uuid)

        return mapping

    def migrate_existing_mappings(self):
        """
        One-time migration to fix source_type for existing mappings.
        Call this during service startup.
        """
        logger.info("Checking for mappings that need migration...")

        all_mappings = self.db.get_all_mappings()
        migrated = 0

        for mapping in all_mappings:
            # Skip if source_type is already set correctly
            current_type = mapping.get("SourceType")
            if current_type == "dynamodb":
                continue

            # Check if this should be a DynamoDB mapping
            arn = mapping["EventSourceArn"]

            should_be_dynamodb = (
                ":dynamodb:" in arn
                or "scylla" in arn.lower()
                or (arn.startswith("S") and len(arn) == 37 and arn.count("-") == 4)
            )

            if should_be_dynamodb:
                logger.info("Migrating mapping %s to DynamoDB type", mapping['UUID'])

                # Re-parse the ARN
                parsed = self._parse_event_source_arn(arn)

                updates = {
                    "SourceType": "dynamodb",
                    "TableName": parsed.get("table_name"),
                    "StreamId": parsed.get("stream_id"),
                }

                # Update normalized ARN if we got one
                if parsed.get("normalized_arn") != arn:
                    updates["EventSourceArn"] = parsed["normalized_arn"]

                self.db.update_mapping(mapping["UUID"], updates)
                migrated += 1

        if migrated > 0:
            logger.info("Migrated %s mappings to correct source type", migrated)
        else:
            logger.info("No mappings needed migration")

    def list_event_source_mappings(self, function_name="") -> Dict:
        """List event source mappings"""
        mappings = self.db.get_all_mappings(function_name)
        return {"EventSourceMappings": mappings}

    def get_event_source_mapping_by_function(
        self, function_name: str
    ) -> Optional[Dict]:
        """Get a single event source mapping by function name"""
        return self.db.get_mapping_by_function_name(function_name)

    def get_event_source_mapping(self, uuid: str) -> Optional[Dict]:
        """Get a single event source mapping by UUID"""
        return self.db.get_mapping_by_uuid(uuid)

    def delete_event_source_mapping(self, uuid: str) -> bool:
        """Delete an event source mapping"""
        if not self.db.mapping_exists(uuid):
            return False

        self._stop_polling(uuid)

        if self.db.delete_mapping(uuid):
            logger.info("Deleted event source mapping %s", uuid)
            return True

        return False

    def update_event_source_mapping(
        self,
        mapping_uuid: str,
        enabled: Optional[bool] = None,
        batch_size: Optional[int] = None,
    ) -> Optional[Dict]:
        mapping = self.db.get_mapping_by_uuid(mapping_uuid)
        if not mapping:
            return None

        updates = {}
        start_after_update = False

        if enabled is not None:
            old_state = mapping["State"]
            new_state = "Enabled" if enabled else "Disabled"
            updates["State"] = new_state

            if old_state == "Disabled" and enabled:
                start_after_update = True
            elif old_state == "Enabled" and not enabled:
                self._stop_polling(mapping_uuid)

        if batch_size is not None:
            updates["BatchSize"] = min(max(batch_size, 1), 10)

        if updates:
            if self.db.update_mapping(mapping_uuid, updates):
                if start_after_update:
                    # Now DB shows Enabled, safe to start polling
                    self._start_polling(mapping_uuid)
                return self.db.get_mapping_by_uuid(mapping_uuid)

        return mapping

    def _start_polling(self, mapping_uuid: str):
        """Start polling thread for a mapping (routes to SQS or DynamoDB handler)"""
        logger.info("Starting polling for %s", mapping_uuid)

        with self._thread_lock("EventSourceMapping._start_polling"):
            if (
                mapping_uuid in self.polling_threads
                and self.polling_threads[mapping_uuid]["thread"].is_alive()
            ):
                logger.info("Polling thread already exists for %s", mapping_uuid)
                return

            mapping = self.db.get_mapping_by_uuid(mapping_uuid)
            if not mapping:
                logger.error("Cannot start polling: mapping %s not found", mapping_uuid)
                return

            stop_event = threading.Event()

            # Use source_type from database to determine polling method
            source_type = mapping.get("SourceType")
            logger.debug("Source Polling Type: %s from %s", source_type, mapping)
            if source_type == "dynamodb":
                target_func = self._poll_dynamodb_stream
                thread_name = f"DDB-Stream-{mapping_uuid[:8]}"
            elif source_type == "sqs":
                target_func = self._poll_queue
                thread_name = f"SQS-{mapping_uuid[:8]}"
            else:
                logger.critical(
                    f"Unknown source_type: {source_type} from Mapping: {mapping}"
                )
                return

            thread = threading.Thread(
                target=target_func,
                args=(mapping_uuid, stop_event),
                daemon=True,
                name=thread_name,
            )

            self.polling_threads[mapping_uuid] = {
                "thread": thread,
                "stop_event": stop_event,
            }

            thread.start()
            logger.info("Started polling thread: %s", thread_name)

    def _stop_polling(self, mapping_uuid: str):
        """Stop polling thread for a mapping"""
        logger.info("Stopping polling for %s", mapping_uuid)

        with self._thread_lock("EventSourceMapping._stop_polling"):
            thread_info = self.polling_threads.get(mapping_uuid)
            if not thread_info:
                logger.warning("No polling thread found for %s", mapping_uuid)
                return

        stop_event = thread_info["stop_event"]
        stop_event.set()

        thread = thread_info["thread"]
        thread.join(timeout=5)

        with self._thread_lock("EventSourceMapping._stop_polling"):
            if mapping_uuid in self.polling_threads:
                del self.polling_threads[mapping_uuid]
                logger.info("Stopped polling thread %s", mapping_uuid)

    def _poll_queue(self, mapping_uuid: str, stop_event: threading.Event):
        """Main polling loop for SQS queues ONLY"""
        logger.info("MappingId:[%s] SQS polling thread starting", mapping_uuid)

        mapping = self.db.get_mapping_by_uuid(mapping_uuid)
        if not mapping:
            logger.error("MappingId:[%s] No mapping found", mapping_uuid)
            return

        # CRITICAL: Verify this is actually an SQS mapping
        source_type = mapping.get("SourceType", "sqs")
        if source_type != "sqs":
            logger.error(
                f"MappingId:[{mapping_uuid}] WRONG HANDLER! "
                f"This is a '{source_type}' mapping, not SQS. "
                f"Should be using _poll_dynamodb_stream instead."
            )
            # Don't disable the mapping - just exit this thread
            return

        queue_name = mapping["QueueName"]
        function_name = mapping["FunctionName"]

        # Wait for service to be running
        wait_start = time.time()
        while not self._running and time.time() - wait_start < 10:
            if stop_event.is_set():
                return
            time.sleep(0.1)

        if not self._running:
            logger.warning("MappingId:[%s] Service not running, exiting", mapping_uuid)
            return

        logger.info(
            f"MappingId:[{mapping_uuid}] SQS polling: {queue_name} -> {function_name}"
        )

        consecutive_failures = 0
        max_failures = 5

        while self._running and not stop_event.is_set():
            try:
                current_mapping = self.db.get_mapping_by_uuid(mapping_uuid)
                if not current_mapping or current_mapping["State"] != "Enabled":
                    logger.info(
                        f"MappingId:[{mapping_uuid}] Mapping disabled, stopping"
                    )
                    break

                batch_size = current_mapping["BatchSize"]
                self.stats[mapping_uuid]["last_poll"] = time.time()

                try:
                    messages = self._receive_messages(queue_name, batch_size)
                except RuntimeError as e:
                    consecutive_failures += 1
                    error_msg = str(e)

                    if consecutive_failures >= max_failures:
                        logger.error(
                            f"MappingId:[{mapping_uuid}] Too many failures ({error_msg}), disabling"
                        )
                        self.db.update_mapping(
                            mapping_uuid,
                            {
                                "State": "Disabled",
                                "StateTransitionReason": error_msg,
                            },
                        )
                        break

                    time.sleep(2 * consecutive_failures)
                    continue

                if not messages:
                    consecutive_failures = 0
                    time.sleep(1)
                    continue

                success = self._invoke_lambda_with_batch_tracked(
                    mapping_uuid, function_name, messages, stop_event
                )

                if success:
                    self._delete_messages(queue_name, messages)
                    self.stats[mapping_uuid]["messages_processed"] += len(messages)
                    self.stats[mapping_uuid]["invocations"] += 1
                    consecutive_failures = 0
                    logger.info(
                        f"MappingId:[{mapping_uuid}] Processed {len(messages)} messages"
                    )
                else:
                    self.stats[mapping_uuid]["messages_failed"] += len(messages)
                    consecutive_failures += 1
                    time.sleep(2 * consecutive_failures)

            except Exception as e:
                logger.error(
                    f"MappingId:[{mapping_uuid}] Error in SQS poll loop: {e}",
                    exc_info=True,
                )
                consecutive_failures += 1
                time.sleep(5)

        logger.info("MappingId:[%s] SQS polling stopped", mapping_uuid)

    def _poll_dynamodb_stream(self, mapping_uuid: str, stop_event: threading.Event):
        """Main polling loop for DynamoDB Streams"""
        logger.info("[%s] DynamoDB Stream polling thread starting", mapping_uuid)

        mapping = self.db.get_mapping_by_uuid(mapping_uuid)
        if not mapping:
            logger.error("[%s] No mapping found", mapping_uuid)
            return

        # Wait for service to be running
        wait_start = time.time()
        while not self._running and time.time() - wait_start < 10:
            if stop_event.is_set():
                return
            time.sleep(0.1)

        if not self._running:
            logger.warning("[%s] Service not running, exiting", mapping_uuid)
            return

        # Initialize DynamoDB Streams poller if not exists
        # if not hasattr(self, 'streams_db'):
        self.streams_db = DynamoDBStreamsDatabase(DB_PATH)
        self.streams_poller = DynamoDBStreamsPoller(
            self.streams_db, self.account_id, self.region
        )

        logger.info("[%s] Starting DynamoDB Stream polling", mapping_uuid)

        try:
            # Discover and poll shards
            self.streams_poller.discover_and_poll_shards(
                mapping_uuid, mapping, stop_event
            )
        except Exception as e:
            logger.error(
                f"[{mapping_uuid}] Fatal error in stream polling: {e}", exc_info=True
            )
            # Disable mapping on fatal error
            self.db.update_mapping(
                mapping_uuid,
                {
                    "State": "Disabled",
                    "StateTransitionReason": f"Fatal error: {str(e)}",
                },
            )
        finally:
            # Cleanup
            if hasattr(self, "streams_poller"):
                self.streams_poller.cleanup_mapping(mapping_uuid)

        logger.info("[%s] DynamoDB Stream polling stopped", mapping_uuid)

    def _ensure_function_ready(
        self, mapping_uuid: str, function_name: str, stop_event: threading.Event
    ) -> bool:
        """Ensure function exists and has a running container"""
        # Ensure function exists by querying the lifecycle (lambda) API via API gateway
        try:
            url = f"{API_BASE}/2015-03-31/functions/{function_name}/configuration"
            resp = requests.get(url, timeout=5)

            if resp.status_code == 200:
                return True

            if resp.status_code == 404:
                logger.error(
                    f"[{mapping_uuid}] Function {function_name} not found (404)"
                )
                return False

            logger.error(
                f"[{mapping_uuid}] Unexpected status from lifecycle API: {resp.status_code} - {resp.text}"
            )
            return False

        except Exception as e:
            logger.error(
                f"[{mapping_uuid}] Error checking function readiness: {e}",
                exc_info=True,
            )
            return False

    def _invoke_lambda_with_batch_tracked(
        self,
        mapping_uuid: str,
        function_name: str,
        messages: list,
        stop_event: threading.Event,
    ) -> bool:
        """Invoke Lambda via HTTP endpoint (same as direct API calls)"""

        # Build SQS event
        records = []
        for msg in messages:
            records.append(
                {
                    "messageId": msg.get("MessageId"),
                    "receiptHandle": msg.get("ReceiptHandle"),
                    "body": msg.get("Body"),
                    "attributes": msg.get("Attributes", {}),
                    "messageAttributes": msg.get("MessageAttributes", {}),
                    "md5OfBody": msg.get("MD5OfBody"),
                    "eventSource": "aws:sqs",
                    "eventSourceARN": f'arn:aws:sqs:{self.region}:{self.account_id}:{messages[0].get("QueueName", "queue")}',
                    "awsRegion": self.region,
                }
            )

        event = {"Records": records}
        logger.debug("Sending Event:%s to Function:%s", event, function_name)
        try:
            url = f"{API_BASE}/2015-03-31/functions/{function_name}/invocations"
            response = requests.post(
                url,
                json=event,
                headers={
                    "Content-Type": "application/json",
                    "X-Amz-Invocation-Type": "RequestResponse",
                },
                timeout=905,  # Lambda max timeout + 5s
            )

            if response.status_code == 200:
                logger.info(
                    f"[{mapping_uuid}] Successfully invoked {function_name} for batch"
                )
                return True
            else:
                logger.error(
                    f"[{mapping_uuid}] Invocation failed: {response.status_code} - {response.text}"
                )
                return False

        except requests.exceptions.Timeout:
            logger.error("[%s] Invocation timeout after 305s", mapping_uuid)
            return False
        except Exception as e:
            logger.error("[%s] Error invoking Lambda: %s", mapping_uuid, e, exc_info=True)
            return False

    def _receive_messages(self, queue_name: str, max_messages: int) -> list:
        """Receive messages from SQS queue with error awareness"""
        try:
            queue_url = f"{API_BASE}/{self.account_id}/{queue_name}"
            payload = {
                "QueueUrl": queue_url,
                "MaxNumberOfMessages": max(1, min(10, max_messages)),
                "WaitTimeSeconds": 0,
            }

            response, status = sqs_request("ReceiveMessage", payload, timeout=30)

            # Handle missing queue
            if status == 404:
                logger.info("Mapping queue not found: %s (status 404)", queue_name)
                raise RuntimeError("QUEUE_NOT_FOUND")

            if status != 200:
                logger.info(
                    f"Unexpected SQS response ({status}) for queue {queue_name}"
                )
                raise RuntimeError(f"SQS_ERROR_{status}")

            if response:
                messages = response.get("Messages", [])
                for msg in messages:
                    msg["QueueName"] = queue_name
                return messages

        except RuntimeError:
            raise  # propagate known errors upward
        except Exception as e:
            logger.error("Error receiving messages from %s: %s", queue_name, e)

        return []

    def _delete_messages(self, queue_name: str, messages: list):
        """Delete successfully processed messages from queue"""
        try:
            queue_url = f"{API_BASE}/{self.account_id}/{queue_name}"

            deleted = 0
            for msg in messages:
                receipt_handle = msg.get("ReceiptHandle")
                message_id = msg.get("MessageId")
                if receipt_handle:
                    payload = {"QueueUrl": queue_url, "ReceiptHandle": receipt_handle}
                    _, status = sqs_request("DeleteMessage", payload, timeout=10)
                    if status == 200:
                        deleted += 1
                        logger.debug("Deleted message %s from %s", message_id, queue_name)
                    else:
                        logger.warning(
                            f"Failed to delete message {message_id} (status {status})"
                        )

            logger.info("Deleted %s/%s messages from %s", deleted, len(messages), queue_name)
        except Exception as e:
            logger.error("Error deleting messages: %s", e, exc_info=True)

    def start(self):
        """Start the event source mapping service"""
        if self._running:
            logger.warning("EMS service already running")
            return

        self._running = True

        # Run migration for existing mappings
        try:
            self.migrate_existing_mappings()
        except Exception as e:
            logger.error("Migration failed: %s", e, exc_info=True)

        # Start cleanup thread
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_worker, daemon=True, name="ESM-Cleanup"
        )
        self.cleanup_thread.start()

        # Start existing mappings
        self.startup_thread = threading.Thread(
            target=self._startup_worker, daemon=True, name="ESM-Startup"
        )
        self.startup_thread.start()

        logger.info("EMS service started")

    def _startup_worker(self):
        """Background worker to load and start existing mappings"""
        try:
            time.sleep(0.5)  # Let other services initialize
            logger.info("StartupWorker has been started")

            enabled_mappings = self.db.get_enabled_mappings()
            if not enabled_mappings:
                logger.info("No existing enabled mappings found")
                return

            logger.info("Restoring %s enabled mapping(s)", len(enabled_mappings))

            for mapping in enabled_mappings:
                uuid_val = mapping["UUID"]
                logger.info(
                    f"Restoring: {uuid_val} - {mapping['QueueName']} -> {mapping['FunctionName']}"
                )
                self._start_polling(uuid_val)

            logger.info("EMS service fully started")
        except Exception as e:
            logger.error("Error in startup worker: %s", e, exc_info=True)

    def _cleanup_worker(self):
        """Cleanup worker - currently unused but kept for future use"""
        logger.info("EMS Cleanup service starting...")
        while self._running:
            try:
                time.sleep(60)
                # Future: Add any periodic cleanup tasks here
            except Exception as e:
                logger.error("Error in cleanup worker: %s", e, exc_info=True)

    def stop(self):
        """Stop all polling threads"""
        logger.info("Stopping EMS service...")
        self._running = False

        uuids_to_stop = list(self.polling_threads.keys())

        for uuid_val in uuids_to_stop:
            self._stop_polling(uuid_val)

        logger.info("EMS service stopped")

    def get_status(self) -> Dict:
        """Get status of all mappings and their polling threads"""
        status = {
            "running": self._running,
            "total_mappings": len(self.db.get_all_mappings()),
            "active_threads": 0,
            "threads": {},
            "stats": dict(self.stats),
            "cleanup_thread": self.cleanup_thread.is_alive(),
            "startup_thread": self.startup_thread.is_alive(),
        }

        with self._thread_lock("EventSourceMapping.get_status"):
            status["active_threads"] = len(self.polling_threads)
            for uuid_val, thread_info in self.polling_threads.items():
                thread = thread_info["thread"]
                mapping = self.db.get_mapping_by_uuid(uuid_val)
                if mapping:
                    status["threads"][uuid_val] = {
                        "queue": mapping["QueueName"],
                        "function": mapping["FunctionName"],
                        "thread_alive": thread.is_alive(),
                        "thread_name": thread.name,
                    }

        return status


class DynamoDBStreamsDatabase:
    """Extended database for DynamoDB Streams tracking"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_streams_tables()

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            logger.error("Database error: %s", e, exc_info=True)
            raise
        finally:
            conn.close()

    def _init_streams_tables(self):
        """Create DynamoDB Streams specific tables"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Shard checkpoints table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS stream_shard_checkpoints (
                    mapping_uuid TEXT NOT NULL,
                    shard_id TEXT NOT NULL,
                    sequence_number TEXT,
                    last_processed REAL NOT NULL,
                    shard_status TEXT NOT NULL DEFAULT 'ACTIVE',
                    parent_shard_id TEXT,
                    PRIMARY KEY (mapping_uuid, shard_id)
                )
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_mapping_shards
                ON stream_shard_checkpoints(mapping_uuid, shard_status)
            """
            )

            # Stream metadata cache
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS stream_metadata (
                    stream_arn TEXT PRIMARY KEY,
                    table_name TEXT NOT NULL,
                    stream_status TEXT NOT NULL,
                    last_checked REAL NOT NULL
                )
            """
            )

            conn.commit()
            logger.info("DynamoDB Streams tables initialized")

    def save_shard_checkpoint(
        self,
        mapping_uuid: str,
        shard_id: str,
        sequence_number: Optional[str],
        parent_shard_id: Optional[str] = None,
    ):
        """Save checkpoint for a shard"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO stream_shard_checkpoints
                (mapping_uuid, shard_id, sequence_number, last_processed, parent_shard_id)
                VALUES (?, ?, ?, ?, ?)
            """,
                (mapping_uuid, shard_id, sequence_number, time.time(), parent_shard_id),
            )
            conn.commit()

    def get_shard_checkpoint(self, mapping_uuid: str, shard_id: str) -> Optional[str]:
        """Get last processed sequence number for a shard"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT sequence_number FROM stream_shard_checkpoints
                WHERE mapping_uuid = ? AND shard_id = ?
            """,
                (mapping_uuid, shard_id),
            )
            row = cursor.fetchone()
            return row["sequence_number"] if row else None

    def get_active_shards(self, mapping_uuid: str) -> List[Dict]:
        """Get all active shards for a mapping"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM stream_shard_checkpoints
                WHERE mapping_uuid = ? AND shard_status = 'ACTIVE'
            """,
                (mapping_uuid,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def mark_shard_exhausted(self, mapping_uuid: str, shard_id: str):
        """Mark a shard as exhausted (closed)"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE stream_shard_checkpoints
                SET shard_status = 'EXHAUSTED'
                WHERE mapping_uuid = ? AND shard_id = ?
            """,
                (mapping_uuid, shard_id),
            )
            conn.commit()
            logger.info("Marked shard %s as exhausted", shard_id)

    def cleanup_mapping_shards(self, mapping_uuid: str):
        """Remove all shard checkpoints for a mapping"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                DELETE FROM stream_shard_checkpoints WHERE mapping_uuid = ?
            """,
                (mapping_uuid,),
            )
            conn.commit()

    def update_stream_metadata(
        self, stream_arn: str, table_name: str, stream_status: str
    ):
        """Cache stream metadata"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO stream_metadata
                (stream_arn, table_name, stream_status, last_checked)
                VALUES (?, ?, ?, ?)
            """,
                (stream_arn, table_name, stream_status, time.time()),
            )
            conn.commit()

    def get_stream_metadata(self, stream_arn: str) -> Optional[Dict]:
        """Get cached stream metadata"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM stream_metadata WHERE stream_arn = ?
            """,
                (stream_arn,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None


class DynamoDBStreamsPoller:
    """Polls DynamoDB Streams and invokes Lambda functions"""

    def __init__(self, db: DynamoDBStreamsDatabase, account_id: str, region: str):
        self.db = db
        self.account_id = account_id
        self.region = region
        self.api_base = os.getenv("AWS_ENDPOINT_URL", "http://api:4566")

        # Initialize boto3 DynamoDB Streams client
        self.dynamodb_endpoint = os.getenv("DYNAMODB_ENDPOINT_URL", "http://ddb:8000")
        client_config = botocore.config.Config(max_pool_connections=1000)
        self.streams_client = boto3.client(
            "dynamodbstreams",
            region_name=region,
            endpoint_url=self.dynamodb_endpoint,
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "localcloud"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "localcloud"),
            config=client_config,
        )
        self.lambda_client = boto3.client(
            "lambda",
            region_name=self.region,
            endpoint_url="http://api:4566",
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "localcloud"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "localcloud"),
            config=client_config,
        )
        # Track active shard pollers per mapping
        self.active_shards: Dict[str, Set[str]] = defaultdict(set)
        self.shard_locks: Dict[str, threading.Lock] = defaultdict(threading.Lock)

    def _dynamodb_streams_request(self, operation: str, data: Dict) -> tuple:
        """Make request to DynamoDB Streams API (directly to Alternator)"""
        for _ in range(0, 3):
            try:
                headers = {
                    "X-Amz-Target": f"DynamoDBStreams_20120810.{operation}",
                    "Content-Type": "application/x-amz-json-1.0",
                }
                # Use DynamoDB endpoint directly
                resp = requests.post(
                    self.dynamodb_endpoint,
                    json=data,
                    headers=headers,
                    timeout=30,
                )

                if resp.status_code == 200:
                    return resp.json(), resp.status_code
                else:
                    logger.warning(
                        f"DynamoDB Streams {operation} returned {resp.status_code}: {resp.text[:200]}"
                    )
                    return None, resp.status_code

            except requests.exceptions.ConnectionError as e:
                logger.error("DynamoDB Streams connection error: %s", e)
                # return None, 503
            # except Exception as e:
            #     logger.error("DynamoDB Streams request error: %s", e, exc_info=True)
            #     return None, 503
            time.sleep(1)

        logger.error(
            f"DynamoDB Streams request error: Failed to query streams, most likely connection issue"
        )
        return None, 503

    def describe_stream(
        self, stream_arn: str, exclusive_start_shard_id: Optional[str] = None
    ) -> Optional[Dict]:
        """Get stream description including shards"""
        # Extract just the stream ID if full ARN provided
        if "/stream/" in stream_arn:
            stream_id = stream_arn.split("/stream/")[-1]
        else:
            stream_id = stream_arn

        # Build request payload
        payload = {"StreamArn": stream_id}

        # Add pagination parameter if provided
        if exclusive_start_shard_id:
            payload["ExclusiveStartShardId"] = exclusive_start_shard_id

        data, status = self._dynamodb_streams_request("DescribeStream", payload)

        if status == 200 and data:
            stream_desc = data.get("StreamDescription", {})

            # Cache metadata
            self.db.update_stream_metadata(
                stream_arn,
                stream_desc.get("TableName", ""),
                stream_desc.get("StreamStatus", "UNKNOWN"),
            )

            return stream_desc

        if status == 400:
            # Stream not found - table likely deleted
            logger.warning("Stream not found: %s", stream_arn)
            return None

        if status == 503:
            # Connection error - service may be starting up
            logger.warning("DynamoDB service unavailable")
            return None

        logger.error("DescribeStream failed with status %s", status)
        return None

    def get_shard_iterator(
        self,
        stream_arn_or_id: str,
        shard_id: str,
        sequence_number: Optional[str] = None,
    ) -> Optional[str]:
        """Get iterator for a shard"""
        try:
            # Extract stream ID for ScyllaDB API
            if "/stream/" in stream_arn_or_id:
                stream_id = stream_arn_or_id.split("/stream/")[-1]
            else:
                stream_id = stream_arn_or_id

            params = {
                "StreamArn": stream_id,
                "ShardId": shard_id,
                "ShardIteratorType": "TRIM_HORIZON",
            }

            # Resume from checkpoint if available
            if sequence_number:
                params["ShardIteratorType"] = "AFTER_SEQUENCE_NUMBER"
                params["SequenceNumber"] = sequence_number

            logger.debug(
                f"GetShardIterator: stream={stream_id}, shard={shard_id}, type={params['ShardIteratorType']}"
            )

            response = self.streams_client.get_shard_iterator(**params)
            iterator = response.get("ShardIterator")

            logger.debug("Got iterator: %s...", iterator[:60] if iterator else 'None')

            return iterator

        except Exception as e:
            logger.error(
                f"GetShardIterator failed for shard {shard_id}: {e}", exc_info=True
            )
            return None

    def get_records(self, shard_iterator: str, limit: int = 100) -> Optional[Dict]:
        """Get records from a shard"""
        try:
            response = self.streams_client.get_records(
                ShardIterator=shard_iterator, Limit=limit
            )

            num_records = len(response.get("Records", []))
            has_next = bool(response.get("NextShardIterator"))
            if num_records:
                logger.info(
                    f"GetRecords returned: {num_records} records, has_next={has_next}"
                )

            return response

        except Exception as e:
            logger.error("GetRecords failed: %s", e, exc_info=True)
            return None

    def poll_shard(
        self,
        mapping_uuid: str,
        mapping: Dict,
        shard_id: str,
        stop_event: threading.Event,
    ):
        """Poll a single shard until exhausted or stopped"""

        # Use stream ID from mapping
        stream_id = mapping.get("StreamId")
        if not stream_id:
            # Fallback to parsing from ARN
            event_source_arn = mapping["EventSourceArn"]
            stream_id = (
                event_source_arn.split("/stream/")[-1]
                if "/stream/" in event_source_arn
                else event_source_arn
            )

        function_name = mapping["FunctionName"]
        batch_size = mapping.get("BatchSize", 100)

        logger.debug("[%s] Started polling shard %s", mapping_uuid, shard_id)

        checkpoint = self.db.get_shard_checkpoint(mapping_uuid, shard_id)

        # Get initial iterator (use stream ID for ScyllaDB)
        shard_iterator = self.get_shard_iterator(stream_id, shard_id, checkpoint)
        if not shard_iterator:
            logger.error(
                f"[{mapping_uuid}] Failed to get iterator for shard {shard_id}"
            )
            return

        consecutive_errors = 0
        max_errors = 5

        while not stop_event.is_set():
            try:
                result = self.get_records(shard_iterator, limit=batch_size)

                if not result:
                    consecutive_errors += 1
                    if consecutive_errors >= max_errors:
                        logger.error(
                            f"[{mapping_uuid}] Too many errors for shard: {shard_id}"
                        )
                        break
                    time.sleep(2**consecutive_errors)
                    continue

                consecutive_errors = 0
                records = result.get("Records", [])
                next_iterator = result.get("NextShardIterator")

                if records:
                    logger.debug(
                        f"[{mapping_uuid}] Got {len(records)} records from shard {shard_id}"
                    )

                    # Use normalized ARN for event
                    event_source_arn = mapping["EventSourceArn"]
                    lambda_event = self._build_lambda_event(event_source_arn, records)

                    success = self._invoke_lambda(function_name, lambda_event)

                    if success:
                        last_seq = records[-1]["dynamodb"]["SequenceNumber"]
                        self.db.save_shard_checkpoint(mapping_uuid, shard_id, last_seq)
                        logger.debug("[%s] Checkpoint updated: %s", mapping_uuid, last_seq)
                    else:
                        logger.warning(
                            f"[{mapping_uuid}] Lambda invocation failed, will retry"
                        )
                        time.sleep(5)
                        continue

                if not next_iterator:
                    logger.info("[%s] Shard %s exhausted", mapping_uuid, shard_id)
                    self.db.mark_shard_exhausted(mapping_uuid, shard_id)
                    break

                shard_iterator = next_iterator

                if not records:
                    time.sleep(1)

            except Exception as e:
                logger.error(
                    f"[{mapping_uuid}] Error polling shard {shard_id}: {e}"
                )  # , exc_info=True
                consecutive_errors += 1
                time.sleep(5)

        logger.info("[%s] Stopped polling shard %s", mapping_uuid, shard_id)

    def _build_lambda_event(self, stream_arn: str, records: List[Dict]) -> Dict:
        """Build Lambda event from DynamoDB Stream records"""
        event_records = []

        for record in records:
            event_record = {
                "eventID": record.get("eventID"),
                "eventName": record.get("eventName"),
                "eventVersion": record.get("eventVersion", "1.1"),
                "eventSource": "aws:dynamodb",
                "awsRegion": self.region,
                "dynamodb": record.get("dynamodb", {}),
                "eventSourceARN": stream_arn,
            }
            event_records.append(event_record)

        return {"Records": event_records}

    def _invoke_lambda(self, function_name: str, event: Dict) -> bool:
        """Invoke Lambda function with event via boto3"""
        try:
            logger.debug("Event Type: %s, Event Data: %s", type(event), event)

            # Bit of a hack, I'm not proud: Convert datetime object values to a string before invoking lambda function
            payload = json.dumps(
                event,
                default=lambda o: (
                    o.isoformat() if isinstance(o, datetime.datetime) else str(o)
                ),
            )

            resp = self.lambda_client.invoke(
                FunctionName=function_name,
                InvocationType="RequestResponse",
                Payload=payload,
            )

            if resp.get("StatusCode") == 200:
                logger.debug("Successfully invoked %s", function_name)
                return True
            else:
                logger.error("Lambda invocation failed: %s - %s", resp['StatusCode'], resp)
                return False

        except Exception as e:
            logger.error("Error invoking Lambda: %s", e)
            return False

    def discover_and_poll_shards(
        self, mapping_uuid: str, mapping: Dict, stop_event: threading.Event
    ):
        """Discover shards and start polling them"""

        # Extract table name and stream ID from mapping
        table_name = mapping.get("TableName")
        stream_id = mapping.get("StreamId")

        if not table_name:
            logger.error("[%s] No table name in mapping", mapping_uuid)
            return

        # Get stream ARN/ID - prefer StreamId if available
        if not stream_id:
            # Try to get from EventSourceArn
            event_source_arn = mapping["EventSourceArn"]
            if "/stream/" in event_source_arn:
                stream_id = event_source_arn.split("/stream/")[-1]
            else:
                # Query DynamoDB for stream
                try:
                    dynamodb = boto3.client(
                        "dynamodb",
                        region_name=self.region,
                        endpoint_url=self.dynamodb_endpoint,
                        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "localcloud"),
                        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "localcloud"),
                    )
                    response = dynamodb.describe_table(TableName=table_name)
                    stream_id = response["Table"].get("LatestStreamArn")
                except Exception as e:
                    logger.error(
                        f"[{mapping_uuid}] Failed to get stream for table {table_name}: {e}"
                    )
                    return

        if not stream_id:
            logger.error("[%s] Could not determine stream ID", mapping_uuid)
            return

        logger.debug(
            f"[{mapping_uuid}] Polling stream {stream_id} for table {table_name}"
        )

        while not stop_event.is_set():
            try:
                # Get ALL shards by paginating
                all_shards = []
                next_shard_id = None
                page_num = 1

                while True:
                    # logger.debug("[%s] Fetching shard page %s...", mapping_uuid, page_num)

                    stream_desc = self.describe_stream(
                        stream_id, exclusive_start_shard_id=next_shard_id
                    )

                    if not stream_desc:
                        logger.error(
                            f"[{mapping_uuid}] Stream not found, stopping polling"
                        )
                        return

                    if stream_desc.get("StreamStatus") != "ENABLED":
                        logger.warning(
                            f"[{mapping_uuid}] Stream not enabled: {stream_desc.get('StreamStatus')}"
                        )
                        break  # Exit pagination loop, will retry in 30s

                    shards = stream_desc.get("Shards", [])
                    all_shards.extend(shards)

                    # logger.info("[%s] Page %s: Got %s shards (total: %s)", mapping_uuid, page_num, len(shards), len(all_shards))

                    # Check for more pages
                    next_shard_id = stream_desc.get("LastEvaluatedShardId")
                    if not next_shard_id:
                        logger.info(
                            f"[{mapping_uuid}] Shard discovery complete: {len(all_shards)} total shards"
                        )
                        break  # No more pages

                    page_num += 1

                if not all_shards:
                    logger.warning("[%s] No shards found", mapping_uuid)
                    time.sleep(10)
                    continue

                # Start polling new shards
                for shard in all_shards:
                    shard_id = shard["ShardId"]

                    if shard_id in self.active_shards[mapping_uuid]:
                        continue

                    parent_shard_id = shard.get("ParentShardId")
                    if (
                        parent_shard_id
                        and parent_shard_id in self.active_shards[mapping_uuid]
                    ):
                        logger.debug(
                            f"[{mapping_uuid}] Waiting for parent shard {parent_shard_id}"
                        )
                        continue

                    logger.debug(
                        f"[{mapping_uuid}] Starting shard poller for {shard_id}"
                    )

                    shard_thread = threading.Thread(
                        target=self.poll_shard,
                        args=(mapping_uuid, mapping, shard_id, stop_event),
                        daemon=True,
                        name=f"Shard-{shard_id[:8]}",
                    )

                    self.active_shards[mapping_uuid].add(shard_id)
                    shard_thread.start()

                time.sleep(60)

            except Exception as e:
                logger.error(
                    f"[{mapping_uuid}] Error in shard discovery: {e}", exc_info=True
                )
                time.sleep(30)

        logger.info("[%s] Shard discovery stopped", mapping_uuid)

    def cleanup_mapping(self, mapping_uuid: str):
        """Clean up all resources for a mapping"""
        with self.shard_locks[mapping_uuid]:
            self.active_shards[mapping_uuid].clear()

        self.db.cleanup_mapping_shards(mapping_uuid)


# --- Flask endpoints to emulate AWS Event Source Mapping API ---
app = Flask(__name__)


def sqs_request(action: str, payload: dict, timeout: int = 30):
    """Proxy SQS actions via the local API gateway (similar to console/API usage)

    action: e.g. 'ReceiveMessage', 'DeleteMessage'
    payload: JSON serializable body (QueueUrl, ReceiptHandle, etc.)
    Returns: (response_json, status_code) or (None, status_code) on failure
    """
    try:
        headers = {
            "Content-Type": "application/x-amz-json-1.0",
            "X-Amz-Target": f"AmazonSQS.{action}",
        }

        resp = requests.post(API_BASE, json=payload, headers=headers, timeout=timeout)
        try:
            data = resp.json()
        except Exception:
            data = None
        return data, resp.status_code
    except Exception as e:
        logger.error("sqs_request error action=%s: %s", action, e, exc_info=True)
        return None, 503


# TODO this is now kind of redundant and messy.
def get_or_create_services():
    global _queue_manager, _esm_service

    # Return existing instance. so called Singleton.
    if _esm_service is not None:
        return _queue_manager, _esm_service

    account_id = os.getenv("AWS_ACCOUNT_ID", "456645664566")
    region = os.getenv("AWS_REGION", "ap-southeast-2")

    _queue_manager = None
    _esm_service = EventSourceMapping(_queue_manager, account_id, region)
    _esm_service.start()

    return _queue_manager, _esm_service


def handle_table_deleted(table_name: str):
    """Called when a DynamoDB table is deleted - stop related mappings"""
    # This should be called from your DynamoDB DeleteTable endpoint

    _, esm_service = get_or_create_services()

    # Find all mappings for this table's stream
    all_mappings = esm_service.db.get_all_mappings()

    for mapping in all_mappings:
        stream_arn = mapping["EventSourceArn"]

        # Check if this mapping is for the deleted table
        if f"table/{table_name}/stream" in stream_arn:
            logger.info(
                f"Table {table_name} deleted, disabling mapping {mapping['UUID']}"
            )

            # Update mapping state
            esm_service.db.update_mapping(
                mapping["UUID"],
                {
                    "State": "Disabled",
                    "StateTransitionReason": f"Table {table_name} was deleted",
                },
            )

            # Stop polling
            esm_service._stop_polling(mapping["UUID"])


@app.route("/health", methods=["GET"])
def healthcheck():
    status = {"status": "ok"}
    return jsonify(status), 201


@app.route("/2015-03-31/event-source-mappings/", methods=["POST"], strict_slashes=False)
def create_mapping_api():
    """Create a new event source mapping"""
    _, esm = get_or_create_services()
    if not esm:
        return jsonify({"message": "EMS service not available"}), 500

    data = request.get_json() or {}
    event_source_arn = data.get("EventSourceArn") or data.get("eventSourceArn")
    function_name = data.get("FunctionName") or data.get("functionName")
    batch_size = int(data.get("BatchSize", 10))
    enabled = data.get("Enabled", True)

    if not event_source_arn or not function_name:
        return jsonify({"message": "EventSourceArn and FunctionName required"}), 400

    try:
        mapping = esm.create_event_source_mapping(
            event_source_arn, function_name, batch_size, enabled
        )
        return jsonify(mapping), 201
    except DuplicateMappingError as e:
        logger.info("Duplicate mapping requested: %s", e)
        return (
            jsonify(
                {"message": "Mapping already exists", "ExistingMapping": e.mapping}
            ),
            409,
        )
    except Exception as e:
        logger.error("Error creating mapping via API: %s", e)
        return jsonify({"message": str(e)}), 500


@app.route("/2015-03-31/event-source-mappings/", methods=["GET"], strict_slashes=False)
def list_mappings_api():
    _, esm = get_or_create_services()
    function_name = request.args.get("FunctionName", default="", type=str)
    if not esm:
        return jsonify({"message": "EMS service not available"}), 500
    return jsonify(esm.list_event_source_mappings(function_name))


@app.route(
    "/2015-03-31/event-source-mappings/<mapping_uuid>",
    methods=["GET"],
    strict_slashes=False,
)
def get_mapping_api(mapping_uuid):
    _, esm = get_or_create_services()
    if not esm:
        return jsonify({"message": "EMS service not available"}), 500
    mapping = esm.get_event_source_mapping(mapping_uuid)
    if not mapping:
        return jsonify({"message": "Mapping not found"}), 404
    return jsonify(mapping)


@app.route(
    "/2015-03-31/event-source-mappings/<mapping_uuid>",
    methods=["PATCH"],
    strict_slashes=False,
)
def update_mapping_api(mapping_uuid):
    _, esm = get_or_create_services()
    if not esm:
        return jsonify({"message": "EMS service not available"}), 500
    data = request.get_json() or {}
    enabled = data.get("Enabled") if "Enabled" in data else None
    batch_size = data.get("BatchSize") if "BatchSize" in data else None

    try:
        updated = esm.update_event_source_mapping(
            mapping_uuid, enabled=enabled, batch_size=batch_size
        )
        if not updated:
            return jsonify({"message": "Mapping not found"}), 404
        return jsonify(updated)
    except Exception as e:
        logger.error("Error updating mapping via API: %s", e)
        return jsonify({"message": str(e)}), 500


@app.route(
    "/2015-03-31/event-source-mappings/<mapping_uuid>",
    methods=["DELETE"],
    strict_slashes=False,
)
def delete_mapping_api(mapping_uuid):
    _, esm = get_or_create_services()
    if not esm:
        return jsonify({"message": "ESM service not available"}), 500
    ok = esm.delete_event_source_mapping(mapping_uuid)
    if not ok:
        return jsonify({"message": "Mapping not found or failed to delete"}), 404
    return ("", 204)


@app.route("/internal/esm/<mapping_uuid>/start", methods=["POST"], strict_slashes=False)
def start_mapping_api(mapping_uuid):
    _, esm = get_or_create_services()
    if not esm:
        return jsonify({"message": "EMS service not available"}), 500
    mapping = esm.get_event_source_mapping(mapping_uuid)
    if not mapping:
        return jsonify({"message": "Mapping not found"}), 404
    esm._start_polling(mapping_uuid)
    return ("", 202)


@app.route("/internal/esm/<mapping_uuid>/stop", methods=["POST"], strict_slashes=False)
def stop_mapping_api(mapping_uuid):
    _, esm = get_or_create_services()
    if not esm:
        return jsonify({"message": "EMS service not available"}), 500
    esm._stop_polling(mapping_uuid)
    return ("", 202)


@app.route("/internal/esm/status", methods=["GET"], strict_slashes=False)
def esm_status_api():
    _, esm = get_or_create_services()
    if not esm:
        return jsonify({"message": "EMS service not available"}), 500
    return jsonify(esm.get_status())


@app.route("/internal/esm/table-deleted", methods=["POST"])
def table_deleted_notification():
    data = request.get_json() or {}
    table_name = data.get("TableName")

    if not table_name:
        return jsonify({"error": "TableName required"}), 400

    _, esm = get_or_create_services()
    if esm:
        handle_table_deleted(table_name)

    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    # Start services and run Flask app for EMS API
    listening_addr = os.getenv("NIMBUS_LISTENING_ADDR", "127.0.0.1")
    logger.info("Starting Event Source Mapping HTTP API on %s:4566", listening_addr)
    get_or_create_services()
    port = int(os.getenv("NIMBUS_HTTP_PORT", "4566"))
    app.run(host=listening_addr, port=port)
