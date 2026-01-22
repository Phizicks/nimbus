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
from typing import Dict, List, Optional
from contextlib import contextmanager
from collections import defaultdict
from enum import Enum
from timedlocking import TimedLock
from flask import Flask, request, jsonify, Response
import logging
import custom_logger

logger = logging.getLogger(__name__)

API_BASE = os.getenv('AWS_ENDPOINT_URL', 'http://api:4566')

DB_PATH = os.getenv('STORAGE_PATH', '/data') + '/event_source_mappings.db'

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

    def __init__(self, db_path: str = "event_source_mappings.db"):
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")

            cursor.execute("""
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
                    UNIQUE(queue_name, function_name)
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_function_name
                ON event_source_mappings(function_name)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_state
                ON event_source_mappings(state)
            """)

            conn.commit()
            logger.info(f"EMS Database initialized at {self.db_path}")

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}", exc_info=True)
            raise
        finally:
            conn.close()

    def create_mapping(self, mapping: Dict) -> bool:
        """Insert a new event source mapping"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO event_source_mappings (
                        uuid, event_source_arn, function_arn, function_name,
                        queue_name, batch_size, state, state_transition_reason,
                        last_modified, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    mapping['UUID'],
                    mapping['EventSourceArn'],
                    mapping['FunctionArn'],
                    mapping['FunctionName'],
                    mapping['QueueName'],
                    mapping['BatchSize'],
                    mapping['State'],
                    mapping['StateTransitionReason'],
                    mapping['LastModified'],
                    time.time()
                ))
                conn.commit()
                logger.info(f"Created mapping in DB: {mapping['UUID']}")
                return True
        except Exception as e:
            logger.error(f"Error creating mapping: {e}", exc_info=True)
            return False

    def get_mapping_by_uuid(self, uuid: str) -> Optional[Dict]:
        """Get a single mapping by UUID"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM event_source_mappings WHERE uuid = ?
                """, (uuid,))
                row = cursor.fetchone()
                if row:
                    return self._row_to_dict(row)
                return None
        except Exception as e:
            logger.error(f"Error getting mapping: {e}", exc_info=True)
            return None

    def get_mapping_by_function_name(self, function_name: str) -> Optional[Dict]:
        """Get a single mapping by function name"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM event_source_mappings WHERE function_name = ?
                """, (function_name,))
                row = cursor.fetchone()
                if row:
                    return self._row_to_dict(row)
                return None
        except Exception as e:
            logger.error(f"Error getting mapping: {e}", exc_info=True)
            return None

    def get_all_mappings(self, function_name: str = '') -> List[Dict]:
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
            logger.error(f"Error getting mappings: {e}", exc_info=True)
            return []

    def get_enabled_mappings(self) -> List[Dict]:
        """Get all enabled mappings"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM event_source_mappings
                    WHERE state = 'Enabled'
                    ORDER BY created_at ASC
                """)
                rows = cursor.fetchall()
                return [self._row_to_dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error getting enabled mappings: {e}", exc_info=True)
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

                set_clauses.append("last_modified = ?")
                values.append(time.time())
                values.append(uuid)

                query = f"""
                    UPDATE event_source_mappings
                    SET {', '.join(set_clauses)}
                    WHERE uuid = ?
                """

                cursor.execute(query, values)
                conn.commit()

                if cursor.rowcount > 0:
                    logger.info(f"Updated mapping: {uuid}")
                    return True
                else:
                    logger.warning(f"No mapping found to update: {uuid}")
                    return False
        except Exception as e:
            logger.error(f"Error updating mapping: {e}", exc_info=True)
            return False

    def delete_mapping(self, uuid: str) -> bool:
        """Delete a mapping"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    DELETE FROM event_source_mappings WHERE uuid = ?
                """, (uuid,))
                conn.commit()

                if cursor.rowcount > 0:
                    logger.info(f"Deleted mapping: {uuid}")
                    return True
                else:
                    logger.warning(f"No mapping found to delete: {uuid}")
                    return False
        except Exception as e:
            logger.error(f"Error deleting mapping: {e}", exc_info=True)
            return False

    def mapping_exists(self, uuid: str) -> bool:
        """Check if a mapping exists"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 1 FROM event_source_mappings WHERE uuid = ? LIMIT 1
                """, (uuid,))
                return cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Error checking mapping existence: {e}", exc_info=True)
            return False

    def get_mapping_by_queue_and_function(self, queue_name: str, function_name: str) -> Optional[Dict]:
        """Get a mapping by queue name and function name (used to detect duplicates)"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM event_source_mappings
                    WHERE queue_name = ? AND function_name = ? LIMIT 1
                """, (queue_name, function_name))
                row = cursor.fetchone()
                if row:
                    return self._row_to_dict(row)
                return None
        except Exception as e:
            logger.error(f"Error getting mapping by queue+function: {e}", exc_info=True)
            return None

    def _row_to_dict(self, row: sqlite3.Row) -> Dict:
        """Convert database row to mapping dictionary"""
        return {
            'UUID': row['uuid'],
            'EventSourceArn': row['event_source_arn'],
            'FunctionArn': row['function_arn'],
            'FunctionName': row['function_name'],
            'QueueName': row['queue_name'],
            'BatchSize': row['batch_size'],
            'State': row['state'],
            'StateTransitionReason': row['state_transition_reason'],
            'LastModified': row['last_modified']
        }

    def _camel_to_snake(self, name: str) -> str:
        """Convert camelCase to snake_case"""
        result = []
        for i, char in enumerate(name):
            if char.isupper() and i > 0:
                result.append('_')
            result.append(char.lower())
        return ''.join(result)

class EventSourceMapping:
    """Manages event source mappings between SQS queues and Lambda functions"""

    def __init__(self, queue_manager, account_id, region):
        self.queue_manager = queue_manager
        self.account_id = account_id
        self.region = region

        self.startup_thread = None
        self.cleanup_thread = None

        # Initialize database
        self.db = EMSDatabase(DB_PATH)

        # Polling threads
        self.polling_threads = {}
        self._thread_lock = TimedLock(warn_threshold=10)

        # Running flag
        self._running = False

        # Stats per mapping
        self.stats = defaultdict(lambda: {
            'messages_received': 0,
            'messages_processed': 0,
            'messages_failed': 0,
            'invocations': 0,
            'last_poll': None
        })

    def create_event_source_mapping(self, event_source_arn: str,
                                   function_name: str,
                                   batch_size: int = 10,
                                   enabled: bool = True) -> Dict:
        """Create a new event source mapping"""
        logger.info(f"Creating ESM: {function_name}, enabled={enabled}")

        queue_name = event_source_arn.split(':')[-1]
        mapping_uuid = str(uuid.uuid4())

        mapping = {
            'UUID': mapping_uuid,
            'EventSourceArn': event_source_arn,
            'FunctionArn': f'arn:aws:lambda:{self.region}:{self.account_id}:function:{function_name}',
            'FunctionName': function_name,
            'QueueName': queue_name,
            'BatchSize': min(max(batch_size, 1), 10),
            'State': 'Enabled' if enabled else 'Disabled',
            'StateTransitionReason': 'User action',
            'LastModified': time.time()
        }
        # Check for existing mapping (avoid UNIQUE constraint failure)
        existing = self.db.get_mapping_by_queue_and_function(queue_name, function_name)
        if existing:
            logger.info(f"Mapping already exists for {queue_name} -> {function_name}: {existing['UUID']}")
            raise DuplicateMappingError(existing)

        # Persist mapping and start polling if enabled
        if not self.db.create_mapping(mapping):
            raise Exception("Failed to create mapping in database")

        if enabled:
            self._start_polling(mapping_uuid)

        logger.info(f"Created event source mapping {mapping_uuid}: {queue_name} -> {function_name}")
        return mapping

    def list_event_source_mappings(self, function_name='') -> Dict:
        """List event source mappings"""
        mappings = self.db.get_all_mappings(function_name)
        return {'EventSourceMappings': mappings}

    def get_event_source_mapping_by_function(self, function_name: str) -> Optional[Dict]:
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
            logger.info(f"Deleted event source mapping {uuid}")
            return True

        return False

    def update_event_source_mapping(self, mapping_uuid: str,
                                    enabled: Optional[bool] = None,
                                    batch_size: Optional[int] = None) -> Optional[Dict]:
        mapping = self.db.get_mapping_by_uuid(mapping_uuid)
        if not mapping:
            return None

        updates = {}
        start_after_update = False

        if enabled is not None:
            old_state = mapping['State']
            new_state = 'Enabled' if enabled else 'Disabled'
            updates['State'] = new_state

            if old_state == 'Disabled' and enabled:
                start_after_update = True
            elif old_state == 'Enabled' and not enabled:
                self._stop_polling(mapping_uuid)

        if batch_size is not None:
            updates['BatchSize'] = min(max(batch_size, 1), 10)

        if updates:
            if self.db.update_mapping(mapping_uuid, updates):
                if start_after_update:
                    # Now DB shows Enabled, safe to start polling
                    self._start_polling(mapping_uuid)
                return self.db.get_mapping_by_uuid(mapping_uuid)

        return mapping

    def _start_polling(self, mapping_uuid: str):
        """Start polling thread for a mapping"""
        logger.info(f"Starting polling for {mapping_uuid}")

        with self._thread_lock("EventSourceMapping._start_polling"):
            if mapping_uuid in self.polling_threads and self.polling_threads[mapping_uuid]['thread'].is_alive():
                logger.info(f"Polling thread already exists for {mapping_uuid}")
                return

            mapping = self.db.get_mapping_by_uuid(mapping_uuid)
            if not mapping:
                logger.error(f"Cannot start polling: mapping {mapping_uuid} not found")
                return

            stop_event = threading.Event()

            thread = threading.Thread(
                target=self._poll_queue,
                args=(mapping_uuid, stop_event),
                daemon=True,
                name=f"ESM-{mapping_uuid}"
            )

            self.polling_threads[mapping_uuid] = {
                'thread': thread,
                'stop_event': stop_event
            }

            thread.start()
            logger.info(f"Started polling thread for {mapping['QueueName']} -> {mapping['FunctionName']}")

    def _stop_polling(self, mapping_uuid: str):
        """Stop polling thread for a mapping"""
        logger.info(f"Stopping polling for {mapping_uuid}")

        with self._thread_lock("EventSourceMapping._stop_polling"):
            thread_info = self.polling_threads.get(mapping_uuid)
            if not thread_info:
                logger.warning(f"No polling thread found for {mapping_uuid}")
                return

        stop_event = thread_info['stop_event']
        stop_event.set()

        thread = thread_info['thread']
        thread.join(timeout=5)

        with self._thread_lock("EventSourceMapping._stop_polling"):
            if mapping_uuid in self.polling_threads:
                del self.polling_threads[mapping_uuid]
                logger.info(f"Stopped polling thread {mapping_uuid}")

    def _poll_queue(self, mapping_uuid: str, stop_event: threading.Event):
        """Main polling loop - REWRITTEN for reliability"""
        logger.info(f"MappingId:[{mapping_uuid}] Polling thread starting")

        mapping = self.db.get_mapping_by_uuid(mapping_uuid)
        if not mapping:
            logger.error(f"MappingId:[{mapping_uuid}] No mapping found")
            return

        queue_name = mapping['QueueName']
        function_name = mapping['FunctionName']

        # Wait for service to be running - might be better to stop/recreate the thread
        wait_start = time.time()
        while not self._running and time.time() - wait_start < 10:
            if stop_event.is_set():
                return
            time.sleep(0.1)

        if not self._running:
            logger.warning(f"MappingId:[{mapping_uuid}] Service not running, exiting")
            return

        logger.info(f"MappingId:[{mapping_uuid}] Polling loop started: {queue_name} -> {function_name}")

        # Track consecutive failures for backoff
        consecutive_failures = 0
        max_failures = 5

        while self._running and not stop_event.is_set():
            try:
                # Check if mapping still enabled
                current_mapping = self.db.get_mapping_by_uuid(mapping_uuid)
                if not current_mapping or current_mapping['State'] != 'Enabled':
                    logger.info(f"MappingId:[{mapping_uuid}] Mapping disabled, stopping")
                    break

                batch_size = current_mapping['BatchSize']

                # Update stats
                self.stats[mapping_uuid]['last_poll'] = time.time()

                # Poll for messages
                try:
                    messages = self._receive_messages(queue_name, batch_size)
                except RuntimeError as e:
                    consecutive_failures += 1
                    if consecutive_failures >= max_failures:
                        logger.error(f"MappingId:[{mapping_uuid}] Polling failed ({e}), disabling mapping")
                        self.db.update_mapping(mapping_uuid, {
                            "State": "Disabled",
                            "StateTransitionReason": str(e),
                        })
                        self.update_event_source_mapping(mapping_uuid, enabled=False)
                        break
                    time.sleep(2 * consecutive_failures)
                    continue

                if not messages:
                    consecutive_failures = 0
                    time.sleep(1)
                    continue

                logger.info(f"MappingId:[{mapping_uuid}] Successfully processed batch")

                # Delete messages from queue
                self._delete_messages(queue_name, messages)
                self.stats[mapping_uuid]['messages_processed'] += len(messages)
                self.stats[mapping_uuid]['invocations'] += 1
                consecutive_failures = 0  # Reset

                # Invoke Lambda with proper tracking
                start_time = time.time()
                success = self._invoke_lambda_with_batch_tracked(
                    mapping_uuid, function_name, messages, stop_event
                )
                elapsed = time.time() - start_time
                logger.warning(f"MappingId:[{mapping_uuid}] Invocation took {elapsed:.2f}s") #warning for visibility

                if not success:
                    # self.stats[mapping_uuid]['messages_processed'] += len(messages)
                    # self.stats[mapping_uuid]['invocations'] += 1
                    # consecutive_failures = 0  # Reset
                    # logger.info(f"MappingId:[{mapping_uuid}] Successfully processed batch")
                # else:
                    # Failed - messages will become visible again
                    self.stats[mapping_uuid]['messages_failed'] += len(messages)
                    consecutive_failures += 1
                    logger.warning(f"[{mapping_uuid}] Failed to process batch (attempt {consecutive_failures})")
                    time.sleep(2 * consecutive_failures)  # Backoff

            except Exception as e:
                logger.error(f"MappingId:[{mapping_uuid}] Error in poll loop: {e}", exc_info=True)
                consecutive_failures += 1
                time.sleep(5)

        logger.info(f"MappingId:[{mapping_uuid}] Polling stopped")

    def _ensure_function_ready(self, mapping_uuid: str, function_name: str,
                               stop_event: threading.Event) -> bool:
        """Ensure function exists and has a running container"""
        # Ensure function exists by querying the lifecycle (lambda) API via API gateway
        try:
            url = f"{API_BASE}/2015-03-31/functions/{function_name}/configuration"
            resp = requests.get(url, timeout=5)

            if resp.status_code == 200:
                return True

            if resp.status_code == 404:
                logger.error(f"[{mapping_uuid}] Function {function_name} not found (404)")
                return False

            logger.error(f"[{mapping_uuid}] Unexpected status from lifecycle API: {resp.status_code} - {resp.text}")
            return False

        except Exception as e:
            logger.error(f"[{mapping_uuid}] Error checking function readiness: {e}", exc_info=True)
            return False

    def _invoke_lambda_with_batch_tracked(self, mapping_uuid: str, function_name: str,
                                        messages: list,
                                        stop_event: threading.Event) -> bool:
        """Invoke Lambda via HTTP endpoint (same as direct API calls)"""

        # Build SQS event
        records = []
        for msg in messages:
            records.append({
                'messageId': msg.get('MessageId'),
                'receiptHandle': msg.get('ReceiptHandle'),
                'body': msg.get('Body'),
                'attributes': msg.get('Attributes', {}),
                'messageAttributes': msg.get('MessageAttributes', {}),
                'md5OfBody': msg.get('MD5OfBody'),
                'eventSource': 'aws:sqs',
                'eventSourceARN': f'arn:aws:sqs:{self.region}:{self.account_id}:{messages[0].get("QueueName", "queue")}',
                'awsRegion': self.region
            })

        event = {'Records': records}
        logger.debug(f"Sending Event:{event} to Function:{function_name}")
        try:
            url = f"{API_BASE}/2015-03-31/functions/{function_name}/invocations"
            response = requests.post(
                url,
                json=event,
                headers={
                    'Content-Type': 'application/json',
                    'X-Amz-Invocation-Type': 'RequestResponse'
                },
                timeout=905  # Lambda max timeout + 5s
            )

            if response.status_code == 200:
                logger.info(f"[{mapping_uuid}] Successfully invoked {function_name} for batch")
                return True
            else:
                logger.error(f"[{mapping_uuid}] Invocation failed: {response.status_code} - {response.text}")
                return False

        except requests.exceptions.Timeout:
            logger.error(f"[{mapping_uuid}] Invocation timeout after 305s")
            return False
        except Exception as e:
            logger.error(f"[{mapping_uuid}] Error invoking Lambda: {e}", exc_info=True)
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
                logger.info(f"Mapping queue not found: {queue_name} (status 404)")
                raise RuntimeError("QUEUE_NOT_FOUND")

            if status != 200:
                logger.info(f"Unexpected SQS response ({status}) for queue {queue_name}")
                raise RuntimeError(f"SQS_ERROR_{status}")

            if response:
                messages = response.get("Messages", [])
                for msg in messages:
                    msg["QueueName"] = queue_name
                return messages

        except RuntimeError:
            raise  # propagate known errors upward
        except Exception as e:
            logger.error(f"Error receiving messages from {queue_name}: {e}")

        return []

    def _delete_messages(self, queue_name: str, messages: list):
        """Delete successfully processed messages from queue"""
        try:
            queue_url = f"{API_BASE}/{self.account_id}/{queue_name}"

            deleted = 0
            for msg in messages:
                receipt_handle = msg.get('ReceiptHandle')
                message_id = msg.get('MessageId')
                if receipt_handle:
                    payload = {
                        'QueueUrl': queue_url,
                        'ReceiptHandle': receipt_handle
                    }
                    _, status = sqs_request('DeleteMessage', payload, timeout=10)
                    if status == 200:
                        deleted += 1
                        logger.debug(f"Deleted message {message_id} from {queue_name}")
                    else:
                        logger.warning(f"Failed to delete message {message_id} (status {status})")

            logger.info(f"Deleted {deleted}/{len(messages)} messages from {queue_name}")
        except Exception as e:
            logger.error(f"Error deleting messages: {e}", exc_info=True)

    def start(self):
        """Start the event source mapping service"""
        if self._running:
            logger.warning("EMS service already running")
            return

        self._running = True

        # Start cleanup thread for stale invocations
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_worker,
            daemon=True,
            name="ESM-Cleanup"
        )
        self.cleanup_thread.start()

        # Start existing mappings in background
        self.startup_thread = threading.Thread(
            target=self._startup_worker,
            daemon=True,
            name="ESM-Startup"
        )
        self.startup_thread.start()

        logger.info("EMS service started")

    def _startup_worker(self):
        """Background worker to load and start existing mappings"""
        try:
            time.sleep(0.5)  # Let other services initialize

            enabled_mappings = self.db.get_enabled_mappings()

            if not enabled_mappings:
                logger.info("No existing enabled mappings found")
                return

            logger.info(f"Restoring {len(enabled_mappings)} enabled mapping(s)")

            for mapping in enabled_mappings:
                uuid_val = mapping['UUID']
                logger.info(
                    f"Restoring: {uuid_val} - "
                    f"{mapping['QueueName']} -> {mapping['FunctionName']}"
                )
                self._start_polling(uuid_val)

            logger.info("EMS service fully started")
        except Exception as e:
            logger.error(f"Error in startup worker: {e}", exc_info=True)

    def _cleanup_worker(self):
        """Cleanup worker - currently unused but kept for future use"""
        logger.info("EMS Cleanup service starting...")
        while self._running:
            try:
                time.sleep(60)
                # Future: Add any periodic cleanup tasks here
            except Exception as e:
                logger.error(f"Error in cleanup worker: {e}", exc_info=True)

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
            'running': self._running,
            'total_mappings': len(self.db.get_all_mappings()),
            'active_threads': 0,
            'threads': {},
            'stats': dict(self.stats),
            'cleanup_thread': self.cleanup_thread.is_alive(),
            'startup_thread': self.startup_thread.is_alive(),
        }

        with self._thread_lock("EventSourceMapping.get_status"):
            status['active_threads'] = len(self.polling_threads)
            for uuid_val, thread_info in self.polling_threads.items():
                thread = thread_info['thread']
                mapping = self.db.get_mapping_by_uuid(uuid_val)
                if mapping:
                    status['threads'][uuid_val] = {
                        'queue': mapping['QueueName'],
                        'function': mapping['FunctionName'],
                        'thread_alive': thread.is_alive(),
                        'thread_name': thread.name
                    }

        return status


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
            'Content-Type': 'application/x-amz-json-1.0',
            'X-Amz-Target': f'AmazonSQS.{action}'
        }

        resp = requests.post(API_BASE, json=payload, headers=headers, timeout=timeout)
        try:
            data = resp.json()
        except Exception:
            data = None
        return data, resp.status_code
    except Exception as e:
        logger.error(f"sqs_request error action={action}: {e}", exc_info=True)
        return None, 503


def get_or_create_services():
    global _queue_manager, _esm_service

    # Return existing instance. so called Singleton.
    if _esm_service is not None:
        return _queue_manager, _esm_service

    account_id = os.getenv('LOCAL_AWS_ACCOUNT_ID', '456645664566')
    region = os.getenv('AWS_REGION', 'ap-southeast-2')

    _queue_manager = None
    _esm_service = EventSourceMapping(_queue_manager, account_id, region)
    _esm_service.start()

    return _queue_manager, _esm_service


@app.route('/health', methods=['GET'])
def healthcheck():
    status = {
        "status": "ok"
    }
    return jsonify(status), 201


@app.route('/2015-03-31/event-source-mappings/', methods=['POST'], strict_slashes=False)
def create_mapping_api():
    """Create a new event source mapping"""
    qm, esm = get_or_create_services()
    if not esm:
        return jsonify({'message': 'EMS service not available'}), 500

    data = request.get_json() or {}
    event_source_arn = data.get('EventSourceArn') or data.get('eventSourceArn')
    function_name = data.get('FunctionName') or data.get('functionName')
    batch_size = int(data.get('BatchSize', 10))
    enabled = data.get('Enabled', True)

    if not event_source_arn or not function_name:
        return jsonify({'message': 'EventSourceArn and FunctionName required'}), 400

    try:
        mapping = esm.create_event_source_mapping(event_source_arn, function_name, batch_size, enabled)
        return jsonify(mapping), 201
    except DuplicateMappingError as e:
        logger.info(f"Duplicate mapping requested: {e}")
        return jsonify({'message': 'Mapping already exists', 'ExistingMapping': e.mapping}), 409
    except Exception as e:
        logger.error(f"Error creating mapping via API: {e}")
        return jsonify({'message': str(e)}), 500


@app.route('/2015-03-31/event-source-mappings/', methods=['GET'], strict_slashes=False)
def list_mappings_api():
    qm, esm = get_or_create_services()
    function_name = request.args.get('FunctionName', default='', type=str)
    if not esm:
        return jsonify({'message': 'EMS service not available'}), 500
    return jsonify(esm.list_event_source_mappings(function_name))


@app.route('/2015-03-31/event-source-mappings/<mapping_uuid>', methods=['GET'], strict_slashes=False)
def get_mapping_api(mapping_uuid):
    qm, esm = get_or_create_services()
    if not esm:
        return jsonify({'message': 'EMS service not available'}), 500
    mapping = esm.get_event_source_mapping(mapping_uuid)
    if not mapping:
        return jsonify({'message': 'Mapping not found'}), 404
    return jsonify(mapping)


@app.route('/2015-03-31/event-source-mappings/<mapping_uuid>', methods=['PATCH'], strict_slashes=False)
def update_mapping_api(mapping_uuid):
    qm, esm = get_or_create_services()
    if not esm:
        return jsonify({'message': 'EMS service not available'}), 500
    data = request.get_json() or {}
    enabled = data.get('Enabled') if 'Enabled' in data else None
    batch_size = data.get('BatchSize') if 'BatchSize' in data else None

    try:
        updated = esm.update_event_source_mapping(mapping_uuid, enabled=enabled, batch_size=batch_size)
        if not updated:
            return jsonify({'message': 'Mapping not found'}), 404
        return jsonify(updated)
    except Exception as e:
        logger.error(f"Error updating mapping via API: {e}")
        return jsonify({'message': str(e)}), 500


@app.route('/2015-03-31/event-source-mappings/<mapping_uuid>', methods=['DELETE'], strict_slashes=False)
def delete_mapping_api(mapping_uuid):
    qm, esm = get_or_create_services()
    if not esm:
        return jsonify({'message': 'ESM service not available'}), 500
    ok = esm.delete_event_source_mapping(mapping_uuid)
    if not ok:
        return jsonify({'message': 'Mapping not found or failed to delete'}), 404
    return ('', 204)


@app.route('/internal/esm/<mapping_uuid>/start', methods=['POST'], strict_slashes=False)
def start_mapping_api(mapping_uuid):
    qm, esm = get_or_create_services()
    if not esm:
        return jsonify({'message': 'EMS service not available'}), 500
    mapping = esm.get_event_source_mapping(mapping_uuid)
    if not mapping:
        return jsonify({'message': 'Mapping not found'}), 404
    esm._start_polling(mapping_uuid)
    return ('', 202)


@app.route('/internal/esm/<mapping_uuid>/stop', methods=['POST'], strict_slashes=False)
def stop_mapping_api(mapping_uuid):
    qm, esm = get_or_create_services()
    if not esm:
        return jsonify({'message': 'EMS service not available'}), 500
    esm._stop_polling(mapping_uuid)
    return ('', 202)


@app.route('/internal/esm/status', methods=['GET'], strict_slashes=False)
def esm_status_api():
    qm, esm = get_or_create_services()
    if not esm:
        return jsonify({'message': 'EMS service not available'}), 500
    return jsonify(esm.get_status())


if __name__ == '__main__':
    # Start services and run Flask app for EMS API
    logger.info('Starting Event Source Mapping HTTP API on 0.0.0.0:4566')
    get_or_create_services()
    port = int(os.getenv('EMS_HTTP_PORT', '4566'))
    app.run(host='0.0.0.0', port=port)

