"""
Lambda Log Manager - Captures and correlates container logs with request IDs
"""

from pathlib import Path
import threading
import time
import logging
import os
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Optional
import docker
import sqlite3
from timedlocking import TimedLock
import sys
import time
import requests

logger = logging.getLogger(__name__)


class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


# AWS API endpoint for centralizing logs
AWS_API_ENDPOINT = os.getenv("AWS_API_ENDPOINT", "http://api:4566")


class CloudWatchLogsDatabase:
    """Manages persistent storage of CloudWatch Logs using SQLite"""

    def __init__(self, db_path=None):
        if db_path is None:
            # Use shared database path so all services access the same logs
            db_path = os.getenv("STORAGE_PATH", "/data") + "/cloudwatch_logs.db"

        self.db_path = db_path
        self.init_db()
        logger.info(f"CloudWatch Logs database initialized at {db_path}")
        self.log_buffers = {}

    def init_db(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Log groups table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS log_groups (
                log_group_name TEXT PRIMARY KEY,
                creation_time INTEGER NOT NULL,
                metric_filter_count INTEGER DEFAULT 0,
                stored_bytes INTEGER DEFAULT 0,
                retention_in_days INTEGER
            )
        """
        )

        # Log streams table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS log_streams (
                log_group_name TEXT NOT NULL,
                log_stream_name TEXT NOT NULL,
                creation_time INTEGER NOT NULL,
                first_event_timestamp INTEGER,
                last_event_timestamp INTEGER,
                last_ingestion_time INTEGER,
                stored_bytes INTEGER DEFAULT 0,
                PRIMARY KEY (log_group_name, log_stream_name),
                FOREIGN KEY (log_group_name) REFERENCES log_groups(log_group_name) ON DELETE CASCADE
            )
        """
        )

        # Log events table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS log_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_group_name TEXT NOT NULL,
                log_stream_name TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                ingestion_time INTEGER NOT NULL,
                message TEXT NOT NULL,
                FOREIGN KEY (log_group_name, log_stream_name)
                    REFERENCES log_streams(log_group_name, log_stream_name) ON DELETE CASCADE
            )
        """
        )

        # Sequence tokens table (for AWS API compatibility)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sequence_tokens (
                log_group_name TEXT NOT NULL,
                log_stream_name TEXT NOT NULL,
                token TEXT NOT NULL,
                PRIMARY KEY (log_group_name, log_stream_name),
                FOREIGN KEY (log_group_name, log_stream_name)
                    REFERENCES log_streams(log_group_name, log_stream_name) ON DELETE CASCADE
            )
        """
        )

        # Create indexes for performance
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_log_events_stream
            ON log_events(log_group_name, log_stream_name, timestamp)
        """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_log_events_timestamp
            ON log_events(timestamp)
        """
        )

        conn.commit()
        conn.close()

    def create_log_group(self, log_group_name, retention_in_days=None):
        """Create a log group"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            creation_time = int(datetime.now(timezone.utc).timestamp() * 1000)
            cursor.execute(
                """
                INSERT INTO log_groups (log_group_name, creation_time, retention_in_days)
                VALUES (?, ?, ?)
            """,
                (log_group_name, creation_time, retention_in_days),
            )
            conn.commit()
            logger.info(f"Created log group: {log_group_name}")
            return True
        except sqlite3.IntegrityError:
            logger.debug(f"Log group already exists: {log_group_name}")
            return False
        finally:
            conn.close()

    def delete_log_group(self, log_group_name):
        """Delete a log group and all its streams/events"""

        # First we need to purge all related log_streams
        # for log_stream in self.list_log_streams(log_group_name):
        #     self.delete_log_stream(log_group_name, log_stream['logStreamName'])
        self.delete_all_loggroup_streams(log_group_name)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            "DELETE FROM log_groups WHERE log_group_name = ?", (log_group_name,)
        )
        deleted = cursor.rowcount > 0

        conn.commit()
        conn.close()

        if deleted:
            logger.info(f"Deleted log group: {log_group_name}")

        return deleted

    def log_group_exists(self, log_group_name: str):
        """Check if a log group exists"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM log_groups WHERE log_group_name = ?", (log_group_name,)
        )
        exists = cursor.fetchone() is not None

        conn.close()
        return exists

    def list_log_groups(self, prefix=None, limit=50):
        """List log groups with optional prefix filter"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if prefix:
            cursor.execute(
                """
                SELECT log_group_name, creation_time, metric_filter_count, stored_bytes, retention_in_days
                FROM log_groups
                WHERE log_group_name LIKE ?
                ORDER BY log_group_name
                LIMIT ?
            """,
                (f"{prefix}%", limit),
            )
        else:
            cursor.execute(
                """
                SELECT log_group_name, creation_time, metric_filter_count, stored_bytes, retention_in_days
                FROM log_groups
                ORDER BY log_group_name
                LIMIT ?
            """,
                (limit,),
            )

        groups = []
        for row in cursor.fetchall():
            groups.append(
                {
                    "logGroupName": row[0],
                    "creationTime": row[1],
                    "metricFilterCount": row[2],
                    "storedBytes": row[3],
                    "retentionInDays": row[4],
                }
            )

        conn.close()
        return groups

    def create_log_stream(self, log_group_name, log_stream_name):
        """Create a log stream"""
        if not self.log_group_exists(log_group_name):
            raise ValueError(f"Log group does not exist: {log_group_name}")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            creation_time = int(datetime.now(timezone.utc).timestamp() * 1000)
            cursor.execute(
                """
                INSERT INTO log_streams (log_group_name, log_stream_name, creation_time)
                VALUES (?, ?, ?)
            """,
                (log_group_name, log_stream_name, creation_time),
            )

            # Initialize sequence token
            cursor.execute(
                """
                INSERT INTO sequence_tokens (log_group_name, log_stream_name, token)
                VALUES (?, ?, ?)
            """,
                (log_group_name, log_stream_name, "0"),
            )

            conn.commit()
            logger.info(f"Created log stream: {log_group_name}/{log_stream_name}")
            return True
        except sqlite3.IntegrityError:
            logger.debug(
                f"Log stream already exists: {log_group_name}/{log_stream_name}"
            )
            return False
        finally:
            conn.close()

    def delete_log_stream(self, log_group_name, log_stream_name):
        """Delete a log stream and all its events"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Nuke all events in a stream
        self.delete_log_stream_events(log_group_name, log_stream_name)

        # Delete log stream
        cursor.execute(
            """
            DELETE FROM log_events
            WHERE log_group_name = ? AND log_stream_name = ?
        """,
            (log_group_name, log_stream_name),
        )

        # Delete the stream itself
        cursor.execute(
            """
            DELETE FROM log_streams
            WHERE log_group_name = ? AND log_stream_name = ?
        """,
            (log_group_name, log_stream_name),
        )

        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()

        if deleted:
            logger.info(f"Deleted log stream: {log_group_name}/{log_stream_name}")

        return deleted

    def delete_all_loggroup_streams(self, log_group_name):
        """Delete a log stream and all its events"""
        if not self.log_group_exists(log_group_name):
            raise ValueError(f"Log group does not exist: {log_group_name}")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Delete events
        cursor.execute(
            """
            DELETE FROM log_events WHERE log_group_name = ?
        """,
            (log_group_name,),
        )

        # Delete log_group_name
        cursor.execute(
            """
            DELETE FROM sequence_tokens WHERE log_group_name = ?
        """,
            (log_group_name,),
        )

        # Delete the log_streams
        cursor.execute(
            """
            DELETE FROM log_streams WHERE log_group_name = ?
        """,
            (log_group_name,),
        )

        conn.commit()
        conn.close()

        return True

    def log_stream_exists(self, log_group_name, log_stream_name):
        """Check if a log stream exists"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT 1 FROM log_streams
            WHERE log_group_name = ? AND log_stream_name = ?
        """,
            (log_group_name, log_stream_name),
        )

        exists = cursor.fetchone() is not None
        conn.close()
        return exists

    def list_log_streams(
        self, log_group_name, prefix=None, limit=50, order_by="LogStreamName"
    ):
        """List log streams in a log group"""
        if not self.log_group_exists(log_group_name):
            raise ValueError(f"Log group does not exist: {log_group_name}")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        order_clause = (
            "log_stream_name"
            if order_by == "LogStreamName"
            else "last_event_timestamp DESC"
        )

        if prefix:
            cursor.execute(
                f"""
                SELECT log_stream_name, creation_time, first_event_timestamp,
                       last_event_timestamp, last_ingestion_time, stored_bytes
                FROM log_streams
                WHERE log_group_name = ? AND log_stream_name LIKE ?
                ORDER BY {order_clause}
                LIMIT ?
            """,
                (log_group_name, f"{prefix}%", limit),
            )
        else:
            cursor.execute(
                f"""
                SELECT log_stream_name, creation_time, first_event_timestamp,
                       last_event_timestamp, last_ingestion_time, stored_bytes
                FROM log_streams
                WHERE log_group_name = ?
                ORDER BY {order_clause}
                LIMIT ?
            """,
                (log_group_name, limit),
            )

        streams = []
        for row in cursor.fetchall():
            streams.append(
                {
                    "logStreamName": row[0],
                    "creationTime": row[1],
                    "firstEventTimestamp": row[2],
                    "lastEventTimestamp": row[3],
                    "lastIngestionTime": row[4],
                    "storedBytes": row[5] or 0,
                }
            )

        conn.close()
        return streams

    def delete_log_stream_events(self, log_group_name, log_stream_name):
        """Put log events to a stream"""
        if not self.log_stream_exists(log_group_name, log_stream_name):
            raise ValueError(
                f"Log stream does not exist: {log_group_name}/{log_stream_name}"
            )

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        ingestion_time = int(datetime.now(timezone.utc).timestamp() * 1000)

        # Delete events
        cursor.execute(
            """
            DELETE FROM log_events WHERE log_group_name = ? AND log_stream_name = ?
        """,
            (log_group_name, log_stream_name),
        )

        conn.commit()
        conn.close()

        logger.info(f"Deleted events from {log_group_name}/{log_stream_name}")
        return True

    def put_log_events(self, log_group_name, log_stream_name, events):
        """Put log events to a stream"""
        if not self.log_stream_exists(log_group_name, log_stream_name):
            self.create_log_stream(
                log_group_name=log_group_name, log_stream_name=log_stream_name
            )

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        ingestion_time = int(datetime.now(timezone.utc).timestamp() * 1000)

        # Insert events
        for event in events:
            cursor.execute(
                """
                INSERT INTO log_events (log_group_name, log_stream_name, timestamp, ingestion_time, message)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    log_group_name,
                    log_stream_name,
                    event["timestamp"],
                    ingestion_time,
                    event["message"],
                ),
            )

        # Update log stream metadata
        cursor.execute(
            """
            UPDATE log_streams
            SET last_event_timestamp = (
                    SELECT MAX(timestamp) FROM log_events
                    WHERE log_group_name = ? AND log_stream_name = ?
                ),
                first_event_timestamp = COALESCE(first_event_timestamp, (
                    SELECT MIN(timestamp) FROM log_events
                    WHERE log_group_name = ? AND log_stream_name = ?
                )),
                last_ingestion_time = ?,
                stored_bytes = (
                    SELECT SUM(LENGTH(message)) FROM log_events
                    WHERE log_group_name = ? AND log_stream_name = ?
                )
            WHERE log_group_name = ? AND log_stream_name = ?
        """,
            (
                log_group_name,
                log_stream_name,
                log_group_name,
                log_stream_name,
                ingestion_time,
                log_group_name,
                log_stream_name,
                log_group_name,
                log_stream_name,
            ),
        )

        # Update log group stored bytes
        cursor.execute(
            """
            UPDATE log_groups
            SET stored_bytes = (
                SELECT SUM(stored_bytes) FROM log_streams WHERE log_group_name = ?
            )
            WHERE log_group_name = ?
        """,
            (log_group_name, log_group_name),
        )

        # Update sequence token
        cursor.execute(
            """
            UPDATE sequence_tokens
            SET token = CAST((CAST(token AS INTEGER) + 1) AS TEXT)
            WHERE log_group_name = ? AND log_stream_name = ?
        """,
            (log_group_name, log_stream_name),
        )

        cursor.execute(
            """
            SELECT token FROM sequence_tokens
            WHERE log_group_name = ? AND log_stream_name = ?
        """,
            (log_group_name, log_stream_name),
        )

        next_token = cursor.fetchone()[0]

        conn.commit()
        conn.close()

        logger.info(f"Added {len(events)} events to {log_group_name}/{log_stream_name}")
        return next_token

    def get_log_events(
        self,
        log_group_name,
        log_stream_name,
        start_time=None,
        end_time=None,
        limit=10000,
        start_from_head=True,
    ):
        """Get log events from a stream"""
        if not self.log_stream_exists(log_group_name, log_stream_name):
            raise ValueError(
                f"Log stream does not exist: {log_group_name}/{log_stream_name}"
            )

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = """
            SELECT timestamp, message, ingestion_time
            FROM log_events
            WHERE log_group_name = ? AND log_stream_name = ?
        """
        params = [log_group_name, log_stream_name]

        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)

        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)

        query += f' ORDER BY timestamp {"ASC" if start_from_head else "DESC"} LIMIT ?'
        params.append(limit)

        cursor.execute(query, params)

        events = []
        for row in cursor.fetchall():
            events.append(
                {"timestamp": row[0], "message": row[1], "ingestionTime": row[2]}
            )

        conn.close()
        return events

    def filter_log_events(
        self,
        log_group_name,
        log_stream_names=None,
        start_time=None,
        end_time=None,
        filter_pattern=None,
        limit=10000,
    ):
        """Filter log events across streams"""
        if not self.log_group_exists(log_group_name):
            raise ValueError(f"Log group does not exist: {log_group_name}")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = """
            SELECT log_stream_name, timestamp, message, ingestion_time
            FROM log_events
            WHERE log_group_name = ?
        """
        params = [log_group_name]

        if log_stream_names:
            placeholders = ",".join("?" * len(log_stream_names))
            query += f" AND log_stream_name IN ({placeholders})"
            params.extend(log_stream_names)

        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)

        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)

        if filter_pattern:
            query += " AND message LIKE ?"
            params.append(f"%{filter_pattern}%")

        query += " ORDER BY timestamp ASC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)

        events = []
        for row in cursor.fetchall():
            events.append(
                {
                    "logStreamName": row[0],
                    "timestamp": row[1],
                    "message": row[2],
                    "ingestionTime": row[3],
                    "eventId": f"{row[0]}/{row[1]}",
                }
            )

        conn.close()
        return events

    def get_sequence_token(self, log_group_name, log_stream_name):
        """Get the current sequence token for a stream"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT token FROM sequence_tokens
            WHERE log_group_name = ? AND log_stream_name = ?
        """,
            (log_group_name, log_stream_name),
        )

        row = cursor.fetchone()
        conn.close()

        return row[0] if row else None


class LogManager:
    """
    Manages log capture and correlation for Lambda container invocations.
    Captures stdout/stderr from containers and associates them with request IDs.
    """

    def __init__(
        self, docker_client, max_logs_per_invocation=1000, log_retention_seconds=300
    ):
        self.docker_client = docker_client
        self.max_logs_per_invocation = max_logs_per_invocation
        self.log_retention_seconds = log_retention_seconds

        # Map request_id -> list of log entries (in-memory for active invocations)
        self.invocation_logs = defaultdict(
            lambda: deque(maxlen=max_logs_per_invocation)
        )

        # Map container_id -> current request_id
        self.container_request_map = {}

        # Map container_id -> log streaming thread
        self.log_threads = {}

        # Container log config for CloudWatch destinations
        self.container_log_config = {}  # container_id -> {log_group, log_stream}

        # Use SQLite database for persistent CloudWatch Logs storage
        self.logs_db = CloudWatchLogsDatabase()

        # Lock for thread-safe operations
        self._lock = TimedLock(warn_threshold=10)

        # Track container_id -> request_id
        self.active_requests = {}

        # Cleanup thread
        self.cleanup_thread = None
        self.running = False

    def start(self):
        """Start the log manager and cleanup thread"""
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        logger.info("LogManager started")

    def stop(self):
        """Stop the log manager"""
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)

        # Stop all log streaming threads
        with self._lock("LogManager.stop"):
            for _, thread in list(self.log_threads.items()):
                if thread.is_alive():
                    thread.join(timeout=1)

        logger.info("LogManager stopped")

    def start_container_logging(
        self, container_id, function_name, log_group_name=None, log_stream_name=None
    ):
        """
        Start capturing logs from a container and send to CloudWatch.
        """
        logger.info(
            f"start_container_logging called: container_id={container_id}, log_group={log_group_name}"
        )

        with self._lock("LogManager.start_container_logging"):
            if container_id in self.log_threads:
                logger.warning(f"Logging already started for container {container_id}")
                return

            # Store log group/stream info for this container (keyed by container ID)
            if log_group_name and log_stream_name:
                if not hasattr(self, "container_log_config"):
                    self.container_log_config = {}
                self.container_log_config[container_id] = {
                    "log_group": log_group_name,
                    "log_stream": log_stream_name,
                }
                logger.info(
                    f"Stored log config for {container_id}: {log_group_name}/{log_stream_name}"
                )

            thread = threading.Thread(
                target=self._stream_container_logs_safe,
                args=(container_id, function_name),
                daemon=True,
            )
            thread.start()

            self.log_threads[container_id] = thread

            logger.info(
                f"Started log streaming thread for container {container_id} -> {log_group_name}/{log_stream_name}"
            )

    def write_start_line(self, request_id, log_group, log_stream):
        """
        Write the START line to CloudWatch Logs (called when invocation begins).
        This emulates AWS Lambda's START line.
        """
        start_line = f"START RequestId: {request_id} Version: $LATEST"

        try:
            timestamp = int(time.time() * 1000)
            self.put_log_events(
                log_group, log_stream, [{"timestamp": timestamp, "message": start_line}]
            )
            logger.debug(
                f"Added START line to CloudWatch for {C.CYAN}{request_id}{C.RESET}"
            )
        except Exception as e:
            logger.error(f"Failed to write START line to CloudWatch: {e}")

    def write_end_line(self, request_id, log_group, log_stream):
        """
        Write the END line to CloudWatch Logs (called when invocation completes).
        """
        end_line = f"END RequestId: {request_id}"
        try:
            timestamp = int(time.time() * 1000)
            self.put_log_events(
                log_group, log_stream, [{"timestamp": timestamp, "message": end_line}]
            )
            logger.debug(
                f"Added END line to CloudWatch for {C.CYAN}{request_id}{C.RESET}"
            )
        except Exception as e:
            logger.error(f"Failed to write END line to CloudWatch: {e}")

    def _stream_container_logs_safe(self, container_id, function_name):
        """Wrapper to catch and log exceptions from _stream_container_logs"""
        try:
            self._stream_container_logs(container_id, function_name)
        except Exception as e:
            logger.error(
                f"Exception in log streaming thread for {container_id}: {e}",
                exc_info=True,
            )
            print(f"THREAD ERROR: {e}", file=sys.stderr, flush=True)

    def _stream_container_logs(self, container_id, function_name):
        """
        Stream logs from a container and associate them with request IDs.
        Also sends logs to CloudWatch log groups/streams.
        Runs in a separate thread per container.
        """
        try:
            logger.debug(
                f"[{time.time()}] _stream_container_logs STARTED for {container_id}"
            )

            # DON'T get request_id here - it will be None since no invocation started yet
            # request_id = self.get_active_request(container_id)  # <-- REMOVE THIS

            # Get CloudWatch log config for this container
            log_config = getattr(self, "container_log_config", {}).get(container_id, {})
            log_group = log_config.get("log_group")
            log_stream = log_config.get("log_stream")

            logger.debug(
                f"CloudWatch config: log_group={log_group}, log_stream={log_stream}"
            )

            # Store buffer reference so we can force flush on demand
            with self._lock("LogManager._stream_container_logs.init_buffer"):
                if not hasattr(self, "log_buffers"):
                    self.log_buffers = {}
                self.log_buffers[container_id] = []

            # Buffer for batching CloudWatch log events
            cloudwatch_buffer = self.log_buffers[container_id]
            last_flush = time.time()
            FLUSH_INTERVAL = 1.0  # Flush every second
            MAX_BATCH_SIZE = 100  # Max events per batch

            container = self.docker_client.containers.get(container_id)

            # Check if container uses a log driver that supports logs() API
            log_config_driver = container.attrs.get("HostConfig", {}).get(
                "LogConfig", {}
            )
            log_driver = log_config_driver.get("Type", "json-file")

            if log_driver not in ["json-file", "journald", "local"]:
                logger.warning(
                    f"Container {container_id} uses '{log_driver}' log driver which "
                    f"doesn't support streaming via Docker API. Logs won't be captured."
                )
                return

            # Stream logs with timestamps
            log_stream_obj = container.logs(
                stream=True,
                follow=True,
                stdout=True,
                stderr=True,
                timestamps=True,
                since=(datetime.now(timezone.utc) - timedelta(days=1)).timestamp(),
            )

            # Track current request_id (updates when invocation changes)
            current_request_id = None

            # Log collecting loop
            for log_line in log_stream_obj:
                try:
                    # Check if request_id changed (only fetch when needed)
                    active_request = self.get_active_request(container_id)
                    if active_request != current_request_id:
                        current_request_id = active_request
                        if active_request:
                            logger.debug(
                                f"Container {container_id} now processing request {C.CYAN}{active_request}{C.RESET}"
                            )

                    # Parse timestamp and message
                    log_str = log_line.decode("utf-8", errors="ignore").rstrip()

                    # Docker timestamps format: "2024-01-01T12:00:00.123456789Z message"
                    # ideally we deal with json directly, work it out later
                    if " " in log_str:
                        timestamp_str, message = log_str.split(" ", 1)
                        try:
                            timestamp_str_clean = timestamp_str.rstrip("Z")
                            timestamp = datetime.fromisoformat(timestamp_str_clean)
                            if timestamp.tzinfo is not None:
                                timestamp = timestamp.replace(tzinfo=None)
                        except:
                            timestamp = datetime.now(timezone.utc).replace(tzinfo=None)
                            message = log_str
                    else:
                        timestamp = datetime.now(timezone.utc).replace(tzinfo=None)
                        message = log_str

                    if not message.strip():
                        continue

                    log_entry = {
                        "timestamp": timestamp,
                        "message": message,
                        "stream": "stdout",
                        "container_id": container_id,
                        "function_name": function_name,
                        "request_id": current_request_id,
                    }

                    # Store log entry for request correlation (in-memory for active invocations)
                    if current_request_id:
                        with self._lock("LogManager._stream_container_logs.store_log"):
                            self.invocation_logs[current_request_id].append(log_entry)

                    # Add to CloudWatch buffer if configured
                    if log_group and log_stream:
                        cloudwatch_event = {
                            "timestamp": int(timestamp.timestamp() * 1000),
                            "message": message,
                        }
                        with self._lock("LogManager._stream_container_logs.append"):
                            cloudwatch_buffer.append(cloudwatch_event)

                    # Server-side debug logging only (not customer-facing)
                    logger.debug(
                        f"[Container:{container_id}][Request:{C.CYAN}{current_request_id}{C.RESET}] {message[:100]}"
                    )

                    # Flush CloudWatch buffer if needed
                    now = time.time()
                    should_flush = len(cloudwatch_buffer) >= MAX_BATCH_SIZE or (
                        cloudwatch_buffer and now - last_flush >= FLUSH_INTERVAL
                    )

                    if should_flush and log_group and log_stream:
                        try:
                            # Copy buffer before sending (thread-safe)
                            with self._lock("LogManager._stream_container_logs.flush"):
                                events_to_send = cloudwatch_buffer.copy()
                                cloudwatch_buffer.clear()

                            if events_to_send:
                                self.put_log_events(
                                    log_group, log_stream, events_to_send
                                )
                                last_flush = now
                                logger.debug(
                                    f"Flushed {len(events_to_send)} events to CloudWatch {log_group}/{log_stream}"
                                )
                        except Exception as e:
                            logger.error(f"Error sending logs to CloudWatch: {e}")
                            # Don't clear buffer on error - will retry next flush

                except Exception as e:
                    logger.error(f"Error processing log line: {e}")
                    continue

            # Final flush of any remaining logs
            if cloudwatch_buffer and log_group and log_stream:
                try:
                    self.put_log_events(log_group, log_stream, cloudwatch_buffer)
                    logger.debug(
                        f"Final flush of {len(cloudwatch_buffer)} events to CloudWatch"
                    )
                except Exception as e:
                    logger.error(f"Error in final flush to CloudWatch: {e}")

        except docker.errors.NotFound:
            logger.warning(f"Container {container_id} not found for logging")
        except Exception as e:
            logger.error(
                f"Error streaming logs from {container_id}: {e}", exc_info=True
            )
        finally:
            logger.warning(
                f"Container {container_id} logging is stopping, container status: {container.status}"
            )
            # Cleanup
            self.stop_container_logging(container_id)
            if hasattr(self, "container_log_config"):
                self.container_log_config.pop(container_id, None)

    def stop_container_logging(self, container_id):
        """
        Stop capturing logs from a container.
        This should be called when a container is stopped/removed.
        """
        with self._lock("LogManager.stop_container_logging"):
            self.container_request_map.pop(container_id, None)
            thread = self.log_threads.pop(container_id, None)
            if thread:
                logger.info(f"Stopped log streaming for container {container_id}")

    def associate_request(self, container_name, container_id, request_id):
        """Associate a request with a container - container_id is the ID"""
        with self._lock("LogManager.associate_request"):
            self.container_request_map[request_id] = container_id
            logger.debug(
                f"Associated request {C.CYAN}{request_id}{C.RESET} with container {container_name}:{container_id}"
            )

    def disassociate_request(self, container_id):
        """
        Remove request association after invocation completes.
        """
        with self._lock("LogManager.disassociate_request"):
            request_id = self.container_request_map.pop(container_id, None)
            if request_id:
                logger.debug(
                    f"Disassociated request {C.CYAN}{request_id}{C.RESET} from container {container_id}"
                )
            return request_id

    def get_invocation_logs(self, request_id):
        """
        Get all logs for a specific invocation.
        Returns list of log entries with timestamps.
        """
        with self._lock("LogManager.get_invocation_logs"):
            if request_id not in self.invocation_logs:
                return []
            return list(self.invocation_logs[request_id])

    def get_invocation_logs_text(self, request_id):
        """
        Get formatted log text for an invocation (CloudWatch-style).
        """
        logs = self.get_invocation_logs(request_id)
        if not logs:
            return ""

        lines = []
        for entry in logs:
            timestamp = entry["timestamp"].strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            lines.append(f"{timestamp} {entry['message']}")

        return "\n".join(lines)

    def get_logs_with_report(
        self,
        request_id,
        duration_ms=0,
        init_duration_ms=None,
        memory_size_mb=128,
        max_memory_mb=None,
    ):
        """Get logs with REPORT line in CloudWatch format"""
        logs = self.get_invocation_logs_text(request_id)

        # Calculate billed duration
        billed_duration = max(100, int((duration_ms + 99) / 100) * 100)

        # Build REPORT line
        report_parts = [
            f"REPORT RequestId: {request_id}",
            f"Duration: {duration_ms:.2f} ms",
            f"Billed Duration: {billed_duration} ms",
            f"Memory Size: {memory_size_mb} MB",
        ]

        if max_memory_mb:
            report_parts.append(f"Max Memory Used: {max_memory_mb} MB")

        # Add Init Duration only for cold starts
        if init_duration_ms is not None:
            report_parts.append(f"Init Duration: {init_duration_ms:.2f} ms")

        report_line = "\t".join(report_parts)

        return f"{logs}\n{report_line}\n"

    def container_logs(self, request_id, duration_ms, init_duration_ms=None):
        """
        Finalize container logs for an invocation by adding START and REPORT lines to CloudWatch.
        """
        # Get container and log stream info from invocation logs
        logs = self.get_invocation_logs(request_id)

        log_group = None
        log_stream = None

        # Find the log group/stream from the container that handled this request
        if logs and len(logs) > 0:
            container_id = logs[0].get("container_id")
            if container_id:
                log_config = getattr(self, "container_log_config", {}).get(
                    container_id, {}
                )
                log_group = log_config.get("log_group")
                log_stream = log_config.get("log_stream")

        # Server-side debug log (not customer-facing)
        logger.debug(
            f"Finalizing logs for RequestId:{C.CYAN}{request_id}{C.RESET} duration:{duration_ms}ms init:{init_duration_ms}ms"
        )

        if not log_group or not log_stream:
            logger.warning(
                f"No CloudWatch log stream found for request {C.CYAN}{request_id}{C.RESET}"
            )
            return

        # Calculate billed duration (rounds up to nearest 100ms, minimum 100ms)
        billed_duration = max(100, int((duration_ms + 99) / 100) * 100)

        # Build REPORT line (AWS Lambda format)
        report_parts = [f"REPORT RequestId: {request_id}"]

        # Add Init Duration FIRST, only for cold starts
        if init_duration_ms is not None:
            report_parts.append(f"Init Duration: {init_duration_ms:.2f} ms")

        # Add remaining metrics
        report_parts.extend(
            [
                f"Duration: {duration_ms:.2f} ms",
                f"Billed Duration: {billed_duration} ms",
                f"Memory Size: 128 MB",
                f"Max Memory Used: 128 MB",  # TODO: Get actual memory usage
            ]
        )

        report_line = "\t".join(report_parts)

        # Write REPORT line to CloudWatch
        try:
            timestamp = int(time.time() * 1000)
            self.put_log_events(
                log_group,
                log_stream,
                [{"timestamp": timestamp, "message": report_line}],
            )
            logger.debug(
                f"Added REPORT line to CloudWatch for {C.CYAN}{request_id}{C.RESET}"
            )
        except Exception as e:
            logger.error(f"Failed to write REPORT line to CloudWatch: {e}")

    def _cleanup_loop(self):
        """
        Periodically clean up old invocation logs.
        """
        while self.running:
            try:
                self._cleanup_old_logs()
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}", exc_info=True)

            time.sleep(60)  # Clean up every minute

    def _cleanup_old_logs(self):
        """
        Remove logs older than retention period.
        """
        cutoff_time = (
            datetime.now(timezone.utc).timestamp() - self.log_retention_seconds
        )

        with self._lock("LogManager._cleanup_old_logs"):
            request_ids_to_remove = []

            for request_id, logs in self.invocation_logs.items():
                if not logs:
                    request_ids_to_remove.append(request_id)
                    continue

                # Check if the most recent log is older than retention period
                most_recent = logs[-1]["timestamp"]
                if most_recent.timestamp() < cutoff_time:
                    request_ids_to_remove.append(request_id)

            for request_id in request_ids_to_remove:
                del self.invocation_logs[request_id]

            if request_ids_to_remove:
                logger.info(
                    f"Cleaned up logs for {len(request_ids_to_remove)} old invocations"
                )

    def create_log_group(self, group_name, retention_in_days=None):
        """Create a log group (now persistent)"""
        try:
            created = self.logs_db.create_log_group(group_name, retention_in_days)
            if created:
                logger.info(f"Created log group: {group_name}")
            return created
        except Exception as e:
            logger.error(f"Error creating log group {group_name}: {e}")
            raise

    def create_log_stream(self, group_name, stream_name):
        """Create a log stream (now persistent)"""
        try:
            # Ensure log group exists first
            if not self.logs_db.log_group_exists(group_name):
                self.create_log_group(group_name)

            created = self.logs_db.create_log_stream(group_name, stream_name)
            if created:
                logger.info(f"Created log stream: {group_name}/{stream_name}")
            else:
                logger.debug(f"Log stream already exists: {group_name}/{stream_name}")
            return created
        except Exception as e:
            logger.error(f"Error creating log stream {group_name}/{stream_name}: {e}")
            raise

    def put_log_events(self, group_name, stream_name, events):
        """Put log events to a stream - forwards to aws_api for centralized storage"""
        # Prefer forwarding to aws_api. Only write locally if forwarding fails.
        try:
            resp_json_or_token = self._forward_logs_to_aws_api(
                group_name, stream_name, events
            )

            # If forward succeeded and returned a token/json, return that.
            if resp_json_or_token:
                logger.info(
                    f"Forwarded {len(events)} events to aws_api for {group_name}/{stream_name}"
                )
                return resp_json_or_token

            # Otherwise, fallback to local storage
            logger.warning(
                f"Forward to aws_api failed for {group_name}/{stream_name}, falling back to local DB"
            )
        except Exception as e:
            logger.warning(f"Exception while forwarding to aws_api: {e}")

        # Local fallback
        try:
            next_token = self.logs_db.put_log_events(group_name, stream_name, events)
            logger.info(
                f"{len(events)} events stored locally for {group_name}/{stream_name}"
            )
            return next_token
        except Exception as e:
            logger.error(
                f"Failed to store logs locally for {group_name}/{stream_name}: {e}"
            )
            raise

    def _forward_logs_to_aws_api(self, group_name, stream_name, events):
        """Forward log events to aws_api's Logs API endpoint"""
        try:
            # Use the Logs API format (X-Amz-Target header)
            payload = {
                "logGroupName": group_name,
                "logStreamName": stream_name,
                "logEvents": events,
            }

            headers = {
                "X-Amz-Target": "Logs_20140328.PutLogEvents",
                "Content-Type": "application/x-amz-json-1.1",
            }

            # Import requests here to avoid circular imports
            resp = requests.post(
                f"{AWS_API_ENDPOINT}/", json=payload, headers=headers, timeout=5
            )

            # Always append a short record so operator can inspect forward attempts
            try:
                logpath = os.path.join(
                    os.getenv("STORAGE_PATH", "/data"), "aws_api_forward.log"
                )
                with open(logpath, "a") as f:
                    f.write(
                        f"{datetime.now(timezone.utc).isoformat()} POST -> {AWS_API_ENDPOINT} status={resp.status_code} group={group_name} stream={stream_name} events={len(events)}\n"
                    )
            except Exception:
                pass

            if resp.status_code in [200, 201]:
                try:
                    j = resp.json()
                    # If API returns nextSequenceToken or similar, return it
                    token = j.get("nextSequenceToken") if isinstance(j, dict) else None
                    return token or j
                except Exception:
                    return True
            else:
                logger.warning(
                    f"AWS API returned {resp.status_code} for PutLogEvents: {resp.text[:200]}"
                )
                return False
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to forward logs to aws_api: {e}")
            return False
        except Exception as e:
            logger.error(f"Error forwarding logs: {e}")
            return False

    def get_log_events(self, group_name, stream_name, events):
        with self._lock("LogManager.get_log_events"):
            self.create_log_stream(group_name, stream_name)
            stream = self.log_groups[group_name][stream_name]

            for e in events:
                stream.append(
                    {
                        "timestamp": e["timestamp"],
                        "message": e["message"],
                        "ingestionTime": int(time.time() * 1000),
                    }
                )

            token = str(int(self.sequence_tokens[(group_name, stream_name)]) + 1)
            self.sequence_tokens[(group_name, stream_name)] = token
            logger.info(f"{len(events)} events added to {group_name}/{stream_name}")
            return token

    def get_or_create_function_log_stream(self, function_name, instance_id):
        """
        Get or create log stream for a Lambda function instance.
        Format: YYYY/MM/DD/[$LATEST]<instance_id>
        """
        from datetime import datetime

        log_group = f"/aws/lambda/{function_name}"

        # Create log group if it doesn't exist
        self.create_log_group(log_group)

        # Generate log stream name in AWS format
        date_prefix = datetime.now(timezone.utc).strftime("%Y/%m/%d")
        log_stream = f"{date_prefix}/[$LATEST]{instance_id}"

        # Create log stream if it doesn't exist
        self.create_log_stream(log_group, log_stream)

        return log_group, log_stream

    def write_container_log_to_cloudwatch(
        self, log_group, log_stream, message, timestamp=None
    ):
        """
        Write a log message to CloudWatch Logs.
        This is called by the container log streaming thread.
        """
        if timestamp is None:
            timestamp = int(time.time() * 1000)
        elif isinstance(timestamp, datetime):
            timestamp = int(timestamp.timestamp() * 1000)

        events = [{"timestamp": timestamp, "message": message}]

        return self.put_log_events(log_group, log_stream, events)

    def list_log_streams(self, log_group: str):
        """List all log streams in a log group"""
        with self._lock("LogManager.list_log_streams"):
            if log_group not in self.log_groups:
                return []

            streams = []
            for stream_name in self.log_groups[log_group].keys():
                stream_data = self.log_groups[log_group][stream_name]

                # Calculate first and last event times
                first_event = stream_data[0]["timestamp"] if stream_data else None
                last_event = stream_data[-1]["timestamp"] if stream_data else None

                streams.append(
                    {
                        "logStreamName": stream_name,
                        "creationTime": first_event,
                        "firstEventTimestamp": first_event,
                        "lastEventTimestamp": last_event,
                        "lastIngestionTime": last_event,
                        "storedBytes": sum(len(e["message"]) for e in stream_data),
                    }
                )

            return streams

    def describe_log_streams(self, log_group, log_stream_name_prefix=None, limit=50):
        """Describe log streams with optional prefix filter"""
        streams = self.list_log_streams(log_group)

        if log_stream_name_prefix:
            streams = [
                s
                for s in streams
                if s["logStreamName"].startswith(log_stream_name_prefix)
            ]

        return streams[:limit]

    def filter_log_events(
        self,
        log_group,
        log_stream_names=None,
        start_time=None,
        end_time=None,
        filter_pattern=None,
        limit=100,
    ):
        """
        Filter log events across streams (like CloudWatch Logs Insights).
        Returns events matching the criteria.
        """
        with self._lock("LogManager.filter_log_events"):
            if log_group not in self.log_groups:
                return []

            events = []

            # Determine which streams to search
            streams_to_search = log_stream_names or list(
                self.log_groups[log_group].keys()
            )

            for stream_name in streams_to_search:
                if stream_name not in self.log_groups[log_group]:
                    continue

                stream_events = self.log_groups[log_group][stream_name]

                for event in stream_events:
                    # Apply time filters
                    if start_time and event["timestamp"] < start_time:
                        continue
                    if end_time and event["timestamp"] > end_time:
                        continue

                    # Apply pattern filter (simple substring match)
                    if filter_pattern and filter_pattern not in event["message"]:
                        continue

                    events.append(
                        {
                            "logStreamName": stream_name,
                            "timestamp": event["timestamp"],
                            "message": event["message"],
                            "ingestionTime": event["ingestionTime"],
                            "eventId": f"{stream_name}:{event['timestamp']}",
                        }
                    )

            # Sort by timestamp and limit
            events.sort(key=lambda e: e["timestamp"])
            return events[:limit]

    def get_container_log_stream_info(self, container_id):
        """Get log group and stream for a container"""
        with self._lock("LogManager.get_container_log_stream_info"):
            # Check if we have a mapping
            if hasattr(self, "container_log_streams"):
                return self.container_log_streams.get(container_id, (None, None))
        return None, None

    def associate_container_with_log_stream(self, container_id, log_group, log_stream):
        """Associate a container with its CloudWatch log stream"""
        with self._lock("LogManager.associate_container_with_log_stream"):
            if not hasattr(self, "container_log_streams"):
                self.container_log_streams = {}
            self.container_log_streams[container_id] = (log_group, log_stream)
            logger.debug(
                f"Associated container {container_id} with {log_group}/{log_stream}"
            )

    def set_active_request(self, container_id: str, request_id: str):
        """
        Associate a request_id with a container for log tracking.
        Called when a container starts processing an invocation.
        """
        with self._lock("LogManager.set_active_request"):
            self.active_requests[container_id] = request_id
            logger.debug(
                f"Set active request for container {container_id}: {request_id}"
            )

    def clear_active_request(self, container_id: str):
        """
        Clear the active request_id for a container.
        Called when a container finishes processing an invocation.
        """
        with self._lock("LogManager.clear_active_request"):
            request_id = self.active_requests.pop(container_id, None)
            if request_id:
                logger.debug(
                    f"Cleared active request for container {container_id}: {request_id}"
                )
            return request_id

    def get_active_request(self, container_id: str) -> Optional[str]:
        """
        Get the currently active request_id for a container.
        Returns None if no active request.
        """
        with self._lock("LogManager.get_active_request"):
            return self.active_requests.get(container_id)


class CloudWatchStyleLogger:
    """
    Exactly as it says, provides CloudWatch-style log formatting and retrieval.
    """

    def __init__(self, log_manager):
        self.log_manager = log_manager
