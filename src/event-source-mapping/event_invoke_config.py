"""
Lambda Event Invoke Config - Manages asynchronous invocation configuration
Handles retry behavior and dead-letter queues for async Lambda invocations
"""

import sqlite3
import logging
import time
import os
from typing import Dict, Optional
from contextlib import contextmanager

logger = logging.getLogger(__name__)

DB_DATA = os.getenv("STORAGE_PATH", "/data") + "/event_invoke_config.db"


class EventInvokeConfigDatabase:
    """Database layer for Event Invoke Configurations"""

    def __init__(self, db_path: str = "event_invoke_config.db"):
        self.db_path = DB_DATA
        self._init_database()

    def _init_database(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Create event invoke config table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS event_invoke_configs (
                    function_name TEXT PRIMARY KEY,
                    qualifier TEXT DEFAULT '$LATEST',
                    maximum_retry_attempts INTEGER DEFAULT 2,
                    maximum_event_age_in_seconds INTEGER DEFAULT 21600,
                    destination_on_success TEXT,
                    destination_on_failure TEXT,
                    last_modified REAL NOT NULL
                )
            """
            )

            conn.commit()
            logger.info(f"Event Invoke Config database initialized at {self.db_path}")

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

    def put_config(self, function_name: str, config: Dict) -> bool:
        """Insert or update event invoke configuration"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO event_invoke_configs (
                        function_name, qualifier, maximum_retry_attempts,
                        maximum_event_age_in_seconds, destination_on_success,
                        destination_on_failure, last_modified
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        function_name,
                        config.get("Qualifier", "$LATEST"),
                        config.get("MaximumRetryAttempts", 2),
                        config.get("MaximumEventAgeInSeconds", 21600),
                        config.get("DestinationConfig", {})
                        .get("OnSuccess", {})
                        .get("Destination"),
                        config.get("DestinationConfig", {})
                        .get("OnFailure", {})
                        .get("Destination"),
                        time.time(),
                    ),
                )
                conn.commit()
                logger.info(f"Saved event invoke config for {function_name}")
                return True
        except Exception as e:
            logger.error(f"Error saving config: {e}", exc_info=True)
            return False

    def get_config(self, function_name: str) -> Optional[Dict]:
        """Get event invoke configuration"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT * FROM event_invoke_configs WHERE function_name = ?
                """,
                    (function_name,),
                )
                row = cursor.fetchone()

                if row:
                    return self._row_to_dict(row)
                return None
        except Exception as e:
            logger.error(f"Error getting config: {e}", exc_info=True)
            return None

    def delete_config(self, function_name: str) -> bool:
        """Delete event invoke configuration"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    DELETE FROM event_invoke_configs WHERE function_name = ?
                """,
                    (function_name,),
                )
                conn.commit()

                if cursor.rowcount > 0:
                    logger.info(f"Deleted event invoke config for {function_name}")
                    return True
                return False
        except Exception as e:
            logger.error(f"Error deleting config: {e}", exc_info=True)
            return False

    def list_configs(self) -> list:
        """List all event invoke configurations"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT * FROM event_invoke_configs
                    ORDER BY last_modified DESC
                """
                )
                rows = cursor.fetchall()
                return [self._row_to_dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error listing configs: {e}", exc_info=True)
            return []

    def _row_to_dict(self, row: sqlite3.Row) -> Dict:
        """Convert database row to config dictionary"""
        config = {
            "FunctionArn": f"arn:aws:lambda:us-east-1:000000000000:function:{row['function_name']}",
            "MaximumRetryAttempts": row["maximum_retry_attempts"],
            "MaximumEventAgeInSeconds": row["maximum_event_age_in_seconds"],
            "LastModified": row["last_modified"],
        }

        # Add destination config if present
        destinations = {}
        if row["destination_on_success"]:
            destinations["OnSuccess"] = {"Destination": row["destination_on_success"]}
        if row["destination_on_failure"]:
            destinations["OnFailure"] = {"Destination": row["destination_on_failure"]}

        if destinations:
            config["DestinationConfig"] = destinations

        return config


class EventInvokeConfig:
    """Manages Lambda Event Invoke Configuration"""

    def __init__(self, account_id: str, region: str, db_path: str = None):
        self.account_id = account_id
        self.region = region

        self.db = EventInvokeConfigDatabase(db_path)

    def put_function_event_invoke_config(
        self,
        function_name: str,
        maximum_retry_attempts: Optional[int] = None,
        maximum_event_age_in_seconds: Optional[int] = None,
        destination_config: Optional[Dict] = None,
        qualifier: str = "$LATEST",
    ) -> Dict:
        """Create or update event invoke configuration"""
        # Validate inputs
        if maximum_retry_attempts is not None:
            if not 0 <= maximum_retry_attempts <= 2:
                raise ValueError("MaximumRetryAttempts must be between 0 and 2")
        else:
            maximum_retry_attempts = 2

        if maximum_event_age_in_seconds is not None:
            if not 60 <= maximum_event_age_in_seconds <= 21600:
                raise ValueError(
                    "MaximumEventAgeInSeconds must be between 60 and 21600"
                )
        else:
            maximum_event_age_in_seconds = 21600

        config = {
            "Qualifier": qualifier,
            "MaximumRetryAttempts": maximum_retry_attempts,
            "MaximumEventAgeInSeconds": maximum_event_age_in_seconds,
        }

        if destination_config:
            config["DestinationConfig"] = destination_config

        if not self.db.put_config(function_name, config):
            raise Exception("Failed to save event invoke configuration")

        saved_config = self.db.get_config(function_name)
        if not saved_config:
            raise Exception("Failed to retrieve saved configuration")

        return saved_config

    def get_function_event_invoke_config(
        self, function_name: str, qualifier: str = "$LATEST"
    ) -> Optional[Dict]:
        """Get event invoke configuration for a function"""
        config = self.db.get_config(function_name)

        if not config:
            # Return default configuration
            return {
                "FunctionArn": f"arn:aws:lambda:{self.region}:{self.account_id}:function:{function_name}",
                "MaximumRetryAttempts": 2,
                "MaximumEventAgeInSeconds": 21600,
                "LastModified": time.time(),
            }

        return config

    def update_function_event_invoke_config(
        self,
        function_name: str,
        maximum_retry_attempts: Optional[int] = None,
        maximum_event_age_in_seconds: Optional[int] = None,
        destination_config: Optional[Dict] = None,
        qualifier: str = "$LATEST",
    ) -> Dict:
        """Update existing event invoke configuration"""
        existing_config = self.db.get_config(function_name)

        if not existing_config:
            raise ValueError(f"No event invoke configuration found for {function_name}")

        update_config = {
            "Qualifier": qualifier,
            "MaximumRetryAttempts": (
                maximum_retry_attempts
                if maximum_retry_attempts is not None
                else existing_config["MaximumRetryAttempts"]
            ),
            "MaximumEventAgeInSeconds": (
                maximum_event_age_in_seconds
                if maximum_event_age_in_seconds is not None
                else existing_config["MaximumEventAgeInSeconds"]
            ),
        }

        # Validate
        if not 0 <= update_config["MaximumRetryAttempts"] <= 2:
            raise ValueError("MaximumRetryAttempts must be between 0 and 2")
        if not 60 <= update_config["MaximumEventAgeInSeconds"] <= 21600:
            raise ValueError("MaximumEventAgeInSeconds must be between 60 and 21600")

        if destination_config is not None:
            update_config["DestinationConfig"] = destination_config

        if not self.db.put_config(function_name, update_config):
            raise Exception("Failed to update event invoke configuration")

        return self.db.get_config(function_name)

    def delete_function_event_invoke_config(
        self, function_name: str, qualifier: str = "$LATEST"
    ) -> bool:
        """Delete event invoke configuration"""
        return self.db.delete_config(function_name)

    def list_function_event_invoke_configs(
        self, function_name: Optional[str] = None
    ) -> Dict:
        """List event invoke configurations"""
        configs = self.db.list_configs()

        if function_name:
            configs = [c for c in configs if function_name in c["FunctionArn"]]

        return {"FunctionEventInvokeConfigs": configs}
