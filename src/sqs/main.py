"""
Complete SQS Implementation using ElasticMQ Backend
Supports FIFO, DLQ, visibility timeout, and standard queue operations
ElasticMQ natively supports all SQS features out of the box.
"""
import boto3
import json
import time
import uuid
import custom_logger
import logging
import sqlite3
import os
from contextlib import contextmanager
from typing import Optional, Dict, List, Any
from flask import Flask, request, jsonify, Response
from timedlocking import TimedLock

logger = logging.getLogger(__name__)
# reduce log level for boto3
logging.getLogger("boto3").setLevel(logging.INFO)
logging.getLogger("botocore").setLevel(logging.INFO)
logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
logging.getLogger('urllib3.poolmanager').setLevel(logging.WARNING)
logging.getLogger('urllib3.util.retry').setLevel(logging.WARNING)

ACCOUNT_ID = "456645664566"
REGION = "ap-southeast-2"

app = Flask(__name__)

# Queue type constants
QUEUE_TYPE_STANDARD = "standard"
QUEUE_TYPE_VISIBILITY = "visibility"
QUEUE_TYPE_DELAY = "delay"

DB_PATH = os.getenv('STORAGE_PATH', '/data') + '/sqs_metadata.db'


class SQSDatabase:
    """Manages SQS queue metadata in SQLite"""

    def __init__(self):
        """Initialize SQS database"""
        self.db_path = DB_PATH
        self.lock = TimedLock(warn_threshold=10)
        self._init_database()
        logger.info(f"SQSDatabase initialized at {DB_PATH}")

    def _init_database(self):
        """Create tables if they don't exist"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Queue metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS queue_metadata (
                    internal_name TEXT PRIMARY KEY,
                    queue_name TEXT NOT NULL,
                    queue_url TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    queue_type TEXT NOT NULL DEFAULT 'standard',
                    attributes TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    UNIQUE(account_id, queue_name)
                )
            """)

            # Index for faster lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_account_queue
                ON queue_metadata(account_id, queue_name)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_account_prefix
                ON queue_metadata(account_id, queue_name)
            """)

            conn.commit()
            logger.info("Database tables initialized")

    @contextmanager
    def _get_connection(self):
        """Get thread-safe database connection with context manager"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def create_queue(self, internal_name: str, queue_name: str, queue_url: str,
                     account_id: str, region: str, queue_type: str,
                     attributes: Dict) -> bool:
        """
        Store queue metadata

        Args:
            internal_name: Internal queue name (e.g., account_standard_queuename)
            queue_name: User-facing queue name
            queue_url: ElasticMQ queue URL
            account_id: AWS account ID
            region: AWS region
            queue_type: Queue type (standard, delay)
            attributes: Queue attributes dict

        Returns:
            True if created, False if already exists
        """
        with self.lock("SQSDatabase.create_queue"):
            with self._get_connection() as conn:
                cursor = conn.cursor()

                try:
                    now = int(time.time())
                    cursor.execute("""
                        INSERT INTO queue_metadata
                        (internal_name, queue_name, queue_url, account_id, region, queue_type,
                         attributes, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        internal_name,
                        queue_name,
                        queue_url,
                        account_id,
                        region,
                        queue_type,
                        json.dumps(attributes),
                        now,
                        now
                    ))
                    conn.commit()
                    logger.info(f"Created queue metadata: {internal_name}")
                    return True

                except sqlite3.IntegrityError:
                    raise Exception(f"Queue already exists: {internal_name}")

    def get_queue(self, internal_name: str) -> Optional[Dict]:
        """Get queue metadata by internal name"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM queue_metadata WHERE internal_name = ?
            """, (internal_name,))

            row = cursor.fetchone()
            if row:
                return {
                    "internal_name": row["internal_name"],
                    "queue_name": row["queue_name"],
                    "queue_url": row["queue_url"],
                    "account_id": row["account_id"],
                    "region": row["region"],
                    "queue_type": row["queue_type"],
                    "attributes": json.loads(row["attributes"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"]
                }
            return None

    def get_queue_by_name(self, account_id: str, queue_name: str) -> Optional[Dict]:
        """Get queue metadata by account and queue name"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM queue_metadata
                WHERE account_id = ? AND queue_name = ? AND queue_type = 'standard'
            """, (account_id, queue_name))

            row = cursor.fetchone()
            if row:
                return {
                    "internal_name": row["internal_name"],
                    "queue_name": row["queue_name"],
                    "queue_url": row["queue_url"],
                    "account_id": row["account_id"],
                    "region": row["region"],
                    "queue_type": row["queue_type"],
                    "attributes": json.loads(row["attributes"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"]
                }
            return None

    def list_queues(self, account_id: str, prefix: Optional[str] = None) -> List[Dict]:
        """
        List all standard queues for an account

        Args:
            account_id: AWS account ID
            prefix: Optional queue name prefix filter

        Returns:
            List of queue metadata dicts
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if prefix:
                cursor.execute("""
                    SELECT * FROM queue_metadata
                    WHERE account_id = ? AND queue_type = 'standard'
                    AND queue_name LIKE ?
                    ORDER BY queue_name
                """, (account_id, f"{prefix}%"))
            else:
                cursor.execute("""
                    SELECT * FROM queue_metadata
                    WHERE account_id = ? AND queue_type = 'standard'
                    ORDER BY queue_name
                """, (account_id,))

            rows = cursor.fetchall()
            return [
                {
                    "internal_name": row["internal_name"],
                    "queue_name": row["queue_name"],
                    "queue_url": row["queue_url"],
                    "account_id": row["account_id"],
                    "region": row["region"],
                    "queue_type": row["queue_type"],
                    "attributes": json.loads(row["attributes"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"]
                }
                for row in rows
            ]

    def update_queue_attributes(self, internal_name: str, attributes: Dict) -> bool:
        """
        Update queue attributes

        Args:
            internal_name: Internal queue name
            attributes: New attributes dict

        Returns:
            True if updated, False if queue not found
        """
        with self.lock("SQSDatabase.update_queue_attributes"):
            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    UPDATE queue_metadata
                    SET attributes = ?, updated_at = ?
                    WHERE internal_name = ?
                """, (json.dumps(attributes), int(time.time()), internal_name))

                conn.commit()

                if cursor.rowcount > 0:
                    logger.info(f"Updated queue attributes: {internal_name}")
                    return True
                else:
                    logger.warning(f"Queue not found for update: {internal_name}")
                    return False

    def delete_queue(self, internal_name: str) -> bool:
        """
        Delete queue metadata

        Args:
            internal_name: Internal queue name

        Returns:
            True if deleted, False if not found
        """
        with self.lock("SQSDatabase.delete_queue"):
            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    DELETE FROM queue_metadata WHERE internal_name = ?
                """, (internal_name,))

                conn.commit()

                if cursor.rowcount > 0:
                    logger.info(f"Deleted queue metadata: {internal_name}")
                    return True
                else:
                    logger.warning(f"Queue not found for deletion: {internal_name}")
                    return False

    def queue_exists(self, internal_name: str) -> bool:
        """Check if queue exists"""
        return self.get_queue(internal_name) is not None

    def get_queue_count(self, account_id: str) -> int:
        """Get total number of queues for an account"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) as count FROM queue_metadata
                WHERE account_id = ? AND queue_type = 'standard'
            """, (account_id,))
            row = cursor.fetchone()
            return row["count"] if row else 0

    def close(self):
        """Close database connection (cleanup)"""
        logger.info("SQSDatabase closed")


class QueueManager:
    """Manages SQS-like queues using ElasticMQ as backend"""

    def __init__(self, account_id: str, region: str,
                 elasticmq_host: str = "sqs-backend", elasticmq_port: int = 9324):
        self.account_id = account_id
        self.region = region
        self.elasticmq_host = elasticmq_host
        self.elasticmq_port = elasticmq_port
        self.elasticmq_url = f"http://{elasticmq_host}:{elasticmq_port}"

        # Initialize database
        self.db = SQSDatabase()

        # Lock for thread-safe operations
        self.lock = TimedLock(warn_threshold=10)

        # SQS client for ElasticMQ
        self.sqs_client = None
        self._init_sqs_client()

        # Queue URL cache
        self.queue_url_cache = {}

        logger.info(f"QueueManager initialized for account {account_id}, region {region}")
        logger.info(f"ElasticMQ endpoint: {self.elasticmq_url}")

    def _init_sqs_client(self):
        """Initialize boto3 SQS client pointing to ElasticMQ"""
        try:
            self.sqs_client = boto3.client(
                'sqs',
                region_name=self.region,
                endpoint_url=self.elasticmq_url,
                aws_access_key_id='localcloud',
                aws_secret_access_key='localcloud'
            )
            logger.info("SQS client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize SQS client: {e}")
            raise

    def start(self):
        """Start QueueManager and verify connection to ElasticMQ"""
        try:
            # Test connection
            self.sqs_client.list_queues()
            logger.info("Successfully connected to ElasticMQ")
        except Exception as e:
            logger.error(f"Failed to connect to ElasticMQ: {e}")
            raise

    def stop(self):
        """Stop QueueManager"""
        logger.info("QueueManager stopped")

    def get_status(self) -> Dict[str, Any]:
        """Get current status of QueueManager"""
        with self.lock("QueueManager.get_status"):
            return {
                "account_id": self.account_id,
                "region": self.region,
                "elasticmq_endpoint": self.elasticmq_url,
                "number_of_queues": self.db.get_queue_count(self.account_id),
            }

    def _internal_name(self, queue_name: str, queue_type: str = QUEUE_TYPE_STANDARD) -> str:
        """Generate internal queue name for ElasticMQ"""
        return f"{queue_name}"

    def _get_dlq_name(self, queue_name: str) -> str:
        """Generate DLQ name for a queue"""
        return f"{queue_name}-dlq"

    def create_queue(self, queue_name: str, queue_type: str = QUEUE_TYPE_STANDARD,
                    attributes: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Create a new SQS queue in ElasticMQ

        Args:
            queue_name: User-facing queue name
            queue_type: Type of queue (standard, fifo, etc.)
            attributes: Queue attributes (VisibilityTimeout, MessageRetentionPeriod, etc.)

        Returns:
            Queue metadata dict
        """
        if not attributes:
            attributes = {}

        internal_name = self._internal_name(queue_name, queue_type)

        # Check if already exists
        if self.db.queue_exists(internal_name):
            logger.info(f"Queue already exists: {queue_name}")
            raise Exception(f"Queue already exists: {queue_name}")

        try:
            # Create DLQ if specified
            dlq_url = None
            if attributes.get('RedrivePolicy'):
                dlq_name = self._get_dlq_name(queue_name)
                dlq_internal_name = self._internal_name(dlq_name, queue_type)

                dlq_response = self.sqs_client.create_queue(
                    QueueName=dlq_internal_name,
                    Attributes={
                        'MessageRetentionPeriod': str(attributes.get('MessageRetentionPeriod', 345600))
                    }
                )
                dlq_url = dlq_response['QueueUrl']
                logger.info(f"Created DLQ: {dlq_name}")

            # Prepare queue attributes
            queue_attrs = {
                'VisibilityTimeout': str(attributes.get('VisibilityTimeout', 30)),
                'MessageRetentionPeriod': str(attributes.get('MessageRetentionPeriod', 345600)),
                'DelaySeconds': str(attributes.get('DelaySeconds', 0)),
                'ReceiveMessageWaitTimeSeconds': str(attributes.get('ReceiveMessageWaitTimeSeconds', 0)),
            }

            # Add redrive policy if DLQ exists
            if dlq_url:
                redrive_policy = {
                    'deadLetterTargetArn': f'arn:aws:sqs:{self.region}:{self.account_id}:{self._get_dlq_name(queue_name)}',
                    'maxReceiveCount': str(attributes.get('maxReceiveCount', 3))
                }
                queue_attrs['RedrivePolicy'] = json.dumps(redrive_policy)

            # Create main queue
            response = self.sqs_client.create_queue(
                QueueName=internal_name,
                Attributes=queue_attrs
            )

            queue_url = response['QueueUrl']
            logger.info(f"Created queue: {queue_name} -> {queue_url}")

            # Store metadata in SQLite
            metadata = {
                "VisibilityTimeout": int(queue_attrs['VisibilityTimeout']),
                "MessageRetentionPeriod": int(queue_attrs['MessageRetentionPeriod']),
                "DelaySeconds": int(queue_attrs['DelaySeconds']),
                "ReceiveMessageWaitTimeSeconds": int(queue_attrs['ReceiveMessageWaitTimeSeconds']),
            }

            if dlq_url:
                metadata['RedrivePolicy'] = {
                    'deadLetterTargetArn': redrive_policy['deadLetterTargetArn'],
                    'maxReceiveCount': int(redrive_policy['maxReceiveCount'])
                }

            self.db.create_queue(
                internal_name=internal_name,
                queue_name=queue_name,
                queue_url=queue_url,
                account_id=self.account_id,
                region=self.region,
                queue_type=queue_type,
                attributes=metadata
            )

            self.queue_url_cache[internal_name] = queue_url

            return {
                'QueueUrl': queue_url,
                'QueueName': queue_name,
                'Attributes': metadata
            }

        except Exception as e:
            logger.error(f"Error creating queue {queue_name}: {e}")
            raise

    def get_queue_url(self, queue_name: str) -> Optional[str]:
        """
        Get queue URL by name

        Args:
            queue_name: User-facing queue name

        Returns:
            Queue URL or None if not found
        """
        internal_name = self._internal_name(queue_name)

        # Check cache first
        if internal_name in self.queue_url_cache:
            return self.queue_url_cache[internal_name]

        # Check database
        queue_meta = self.db.get_queue_by_name(self.account_id, queue_name)
        if queue_meta:
            url = queue_meta['queue_url']
            self.queue_url_cache[internal_name] = url
            return url

        # Try to get from ElasticMQ
        try:
            response = self.sqs_client.get_queue_url(
                QueueName=internal_name,
                QueueOwnerAWSAccountId=self.account_id
            )
            url = response['QueueUrl']
            self.queue_url_cache[internal_name] = url
            return url
        except Exception as e:
            logger.info(f"Queue not found: {queue_name} - {e}")
            return None

    def list_queues(self, prefix: Optional[str] = None) -> List[str]:
        """
        List queues for this account

        Args:
            prefix: Optional queue name prefix filter

        Returns:
            List of queue URLs
        """
        try:
            response = self.sqs_client.list_queues()
            queue_urls = response.get('QueueUrls', [])

            # Filter by prefix if provided
            if prefix:
                queue_urls = [url for url in queue_urls if prefix in url]

            return queue_urls
        except Exception as e:
            logger.error(f"Error listing queues: {e}")
            return []

    def delete_queue(self, queue_name: str) -> bool:
        """
        Delete a queue

        Args:
            queue_name: User-facing queue name

        Returns:
            True if deleted successfully
        """
        try:
            queue_url = self.get_queue_url(queue_name)
            if not queue_url:
                logger.info(f"Queue not found: {queue_name}")
                return False

            self.sqs_client.delete_queue(QueueUrl=queue_url)

            internal_name = self._internal_name(queue_name)
            self.db.delete_queue(internal_name)

            # Remove from cache
            if internal_name in self.queue_url_cache:
                del self.queue_url_cache[internal_name]

            logger.info(f"Deleted queue: {queue_name}")
            return True

        except Exception as e:
            logger.error(f"Error deleting queue {queue_name}: {e}")
            return False

    def send_message(self, queue_name: str, message_body: str,
                    message_attributes: Optional[Dict] = None,
                    delay_seconds: Optional[int] = None) -> Optional[Dict]:
        """
        Send a message to a queue

        Args:
            queue_name: User-facing queue name
            message_body: Message body
            message_attributes: Optional message attributes
            delay_seconds: Optional message delay

        Returns:
            Message metadata (MessageId, MD5OfMessageBody, etc.)
        """
        try:
            queue_url = self.get_queue_url(queue_name)
            if not queue_url:
                logger.info(f"Queue not found: {queue_name}")
                return None

            kwargs = {
                'QueueUrl': queue_url,
                'MessageBody': message_body
            }

            if message_attributes:
                kwargs['MessageAttributes'] = message_attributes

            if delay_seconds is not None:
                kwargs['DelaySeconds'] = delay_seconds

            response = self.sqs_client.send_message(**kwargs)
            logger.info(f"Sent message to {queue_name}: {response.get('MessageId')}")
            return response

        except Exception as e:
            logger.error(f"Error sending message to {queue_name}: {e}")
            return None

    def send_message_batch(self, queue_name: str, messages: List[Dict]) -> Optional[Dict]:
        """
        Send batch of messages to a queue

        Args:
            queue_name: User-facing queue name
            messages: List of message dicts with Id, MessageBody, etc.

        Returns:
            Batch response
        """
        try:
            queue_url = self.get_queue_url(queue_name)
            if not queue_url:
                logger.info(f"Queue not found: {queue_name}")
                return None

            response = self.sqs_client.send_message_batch(
                QueueUrl=queue_url,
                Entries=messages
            )
            logger.info(f"Sent {len(messages)} messages to {queue_name}")
            return response

        except Exception as e:
            logger.error(f"Error sending batch to {queue_name}: {e}")
            return None

    def receive_message(self, queue_name: str, max_messages: int = 1,
                       visibility_timeout: Optional[int] = None,
                       wait_time_seconds: int = 0) -> Optional[Dict]:
        """
        Receive messages from a queue

        Args:
            queue_name: User-facing queue name
            max_messages: Max messages to receive (1-10)
            visibility_timeout: Override queue's visibility timeout
            wait_time_seconds: Long polling wait time

        Returns:
            Receive response with messages
        """
        try:
            queue_url = self.get_queue_url(queue_name)
            if not queue_url:
                logger.info(f"Queue not found: {queue_name}")
                return None

            kwargs = {
                'QueueUrl': queue_url,
                'MaxNumberOfMessages': max(1, min(10, max_messages)),
                'MessageAttributeNames': ['All'],
                'WaitTimeSeconds': wait_time_seconds
            }

            if visibility_timeout is not None:
                kwargs['VisibilityTimeout'] = visibility_timeout

            response = self.sqs_client.receive_message(**kwargs)
            return response

        except Exception as e:
            logger.error(f"Error receiving from {queue_name}: {e}")
            return None

    def delete_message(self, queue_name: str, receipt_handle: str) -> bool:
        """
        Delete a message from a queue

        Args:
            queue_name: User-facing queue name
            receipt_handle: Receipt handle from receive_message

        Returns:
            True if deleted successfully
        """
        try:
            queue_url = self.get_queue_url(queue_name)
            if not queue_url:
                logger.info(f"Queue not found: {queue_name}")
                return False

            self.sqs_client.delete_message(
                QueueUrl=queue_url,
                ReceiptHandle=receipt_handle
            )
            return True

        except Exception as e:
            logger.error(f"Error deleting message: {e}")
            return False

    def delete_message_batch(self, queue_name: str, entries: List[Dict]) -> Optional[Dict]:
        """
        Delete batch of messages from a queue

        Args:
            queue_name: User-facing queue name
            entries: List of {Id, ReceiptHandle} dicts

        Returns:
            Batch response
        """
        try:
            queue_url = self.get_queue_url(queue_name)
            if not queue_url:
                logger.info(f"Queue not found: {queue_name}")
                return None

            response = self.sqs_client.delete_message_batch(
                QueueUrl=queue_url,
                Entries=entries
            )
            return response

        except Exception as e:
            logger.error(f"Error deleting batch: {e}")
            return None

    def change_message_visibility(self, queue_name: str, receipt_handle: str,
                                 visibility_timeout: int) -> bool:
        """
        Change visibility timeout for a message

        Args:
            queue_name: User-facing queue name
            receipt_handle: Receipt handle from receive_message
            visibility_timeout: New visibility timeout in seconds

        Returns:
            True if successful
        """
        try:
            queue_url = self.get_queue_url(queue_name)
            if not queue_url:
                logger.info(f"Queue not found: {queue_name}")
                return False

            self.sqs_client.change_message_visibility(
                QueueUrl=queue_url,
                ReceiptHandle=receipt_handle,
                VisibilityTimeout=visibility_timeout
            )
            return True

        except Exception as e:
            logger.error(f"Error changing message visibility: {e}")
            return False

    def change_message_visibility_batch(self, queue_name: str,
                                       entries: List[Dict]) -> Optional[Dict]:
        """
        Change visibility timeout for batch of messages

        Args:
            queue_name: User-facing queue name
            entries: List of {Id, ReceiptHandle, VisibilityTimeout} dicts

        Returns:
            Batch response
        """
        try:
            queue_url = self.get_queue_url(queue_name)
            if not queue_url:
                logger.info(f"Queue not found: {queue_name}")
                return None

            response = self.sqs_client.change_message_visibility_batch(
                QueueUrl=queue_url,
                Entries=entries
            )
            return response

        except Exception as e:
            logger.error(f"Error changing visibility batch: {e}")
            return None

    def get_queue_attributes(self, queue_name: str,
                            attribute_names: Optional[List[str]] = None) -> Optional[Dict]:
        """
        Get queue attributes

        Args:
            queue_name: User-facing queue name
            attribute_names: List of attributes to retrieve (or ['All'])

        Returns:
            Dictionary of attributes
        """
        try:
            queue_url = self.get_queue_url(queue_name)
            if not queue_url:
                logger.info(f"Queue not found: {queue_name}")
                return None

            if not attribute_names:
                attribute_names = ['All']

            response = self.sqs_client.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=attribute_names
            )
            return response.get('Attributes', {})

        except Exception as e:
            logger.error(f"Error getting queue attributes: {e}")
            return None

    def set_queue_attributes(self, queue_name: str, attributes: Dict) -> bool:
        """
        Set queue attributes

        Args:
            queue_name: User-facing queue name
            attributes: Dictionary of attributes to set

        Returns:
            True if successful
        """
        try:
            queue_url = self.get_queue_url(queue_name)
            if not queue_url:
                logger.info(f"Queue not found: {queue_name}")
                return False

            self.sqs_client.set_queue_attributes(
                QueueUrl=queue_url,
                Attributes=attributes
            )
            return True

        except Exception as e:
            logger.error(f"Error setting queue attributes: {e}")
            return False


# Initialize queue manager
queue_manager = None


@app.before_request
def initialize():
    """Initialize queue manager on first request"""
    global queue_manager
    if queue_manager is None:
        queue_manager = QueueManager(ACCOUNT_ID, REGION)
        queue_manager.start()
    logger.debug(f"Request: {request.method} {request.path} from {request.remote_addr}, Headers: {dict(request.headers)}")


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok'}), 200


@app.route('/healthcheck', methods=['GET'])
def healthcheck():
    """Get queue manager status"""
    if queue_manager:
        return jsonify({ "is_ready": queue_manager.sqs_client is not None }), 200
    return jsonify({'error': 'Not initialized'}), 503

@app.route('/status', methods=['GET'])
def status():
    """Get queue manager status"""
    if queue_manager:
        return jsonify(queue_manager.get_status()), 200
    return jsonify({'error': 'Not initialized'}), 503


@app.route('/', methods=['POST'], strict_slashes=False)
def handle_sqs_request():
    """Main SQS request handler - routes to appropriate action"""
    try:
        # Extract action from X-Amz-Target header or Action parameter
        action = None
        target = request.headers.get('X-Amz-Target', '')

        if target and '.' in target:
            action = target.split('.')[-1]  # "AmazonSQS.CreateQueue" → "CreateQueue"
        else:
            # Try form data or JSON body
            if request.form:
                action = request.form.get('Action')
            elif request.is_json:
                action = request.json.get('Action')

        if not action:
            return error_response('MissingAction', 'Missing Action parameter'), 400

        logger.info(f"Handling action: {action} - Data: {request.form}")

        # Route to appropriate handler
        action_handlers = {
            'CreateQueue': handle_create_queue,
            'GetQueueUrl': handle_get_queue_url,
            'ListQueues': handle_list_queues,
            'DeleteQueue': handle_delete_queue,
            'SendMessage': handle_send_message,
            'SendMessageBatch': handle_send_message_batch,
            'ReceiveMessage': handle_receive_message,
            'DeleteMessage': handle_delete_message,
            'DeleteMessageBatch': handle_delete_message_batch,
            'ChangeMessageVisibility': handle_change_message_visibility,
            'ChangeMessageVisibilityBatch': handle_change_message_visibility_batch,
            'GetQueueAttributes': handle_get_queue_attributes,
            'SetQueueAttributes': handle_set_queue_attributes,
            'PurgeQueue': handle_purge_queue,
        }

        handler = action_handlers.get(action)
        if not handler:
            return error_response('InvalidAction', f'Unrecognized action: {action}'), 400

        return handler()

    except Exception as e:
        logger.error(f"Error handling request: {e}", exc_info=True)
        return error_response('InternalError', str(e)), 500


def get_request_param(name: str, default=None):
    """Extract parameter from request (form data or JSON)"""
    # logger.debug(f"Content-Type: {request.content_type}")
    # logger.debug(f"Form data: {dict(request.form)}")
    # logger.debug(f"JSON data: {request.json if request.is_json else 'Not JSON'}")
    # logger.debug(f"Raw data: {request.data}")
    # logger.debug(f"Args: {dict(request.args)}")
    if request.form:
        return request.form.get(name, default)

    # Try to get JSON data
    try:
        data = request.get_json(force=True, silent=True)
        if data:
            # logger.debug(f"Returning: Name:{name} -> {data.get(name, default)}")
            return data.get(name, default)
    except:
        pass

    try:
        logger.debug(f"Returning: {json.loads(request.data)}")
        return json.loads(request.data)
    except:
        logger.debug(f"Returning: {default}")
        return default

def error_response(error_type: str, message: str) -> Response:
    """Generate AWS SQS-style error response"""
    return jsonify({
        "__type": f"{error_type}",
        "message": message
    })


def success_response(data: Dict) -> Response:
    """Generate success response"""
    return jsonify(data)


def handle_create_queue():
    """Handle CreateQueue action"""
    try:
        logger.info(f"Content-Type: {request.content_type}")
        logger.info(f"Form data: {dict(request.form)}")
        logger.info(f"JSON data: {request.json if request.is_json else 'Not JSON'}")
        logger.info(f"Raw data: {request.data}")
        logger.info(f"Args: {dict(request.args)}")
        queue_name = get_request_param('QueueName')
        if not queue_name:
            return error_response('MissingParameter', 'QueueName is required'), 400

        # Extract attributes
        attributes = {}
        for key in ['VisibilityTimeout', 'MessageRetentionPeriod', 'DelaySeconds',
                   'ReceiveMessageWaitTimeSeconds', 'maxReceiveCount']:
            value = get_request_param(f'Attribute.Name.{key}') or get_request_param(key)
            if value:
                attributes[key] = int(value) if value.isdigit() else value

        # Check for RedrivePolicy
        redrive_policy = get_request_param('RedrivePolicy')
        if redrive_policy:
            attributes['RedrivePolicy'] = redrive_policy

        result = queue_manager.create_queue(queue_name, attributes=attributes)

        return success_response({
            'QueueUrl': result['QueueUrl']
        }), 200

    except Exception as e:
        logger.error(f"Error in CreateQueue: {e}")
        return error_response('InternalError', str(e)), 500


def handle_get_queue_url():
    """Handle GetQueueUrl action"""
    try:
        queue_name = get_request_param('QueueName')
        if not queue_name:
            return error_response('MissingParameter', 'QueueName is required'), 400

        queue_url = queue_manager.get_queue_url(queue_name)
        if not queue_url:
            return error_response('QueueDoesNotExist', f'Queue {queue_name} does not exist'), 404

        return success_response({
            'QueueUrl': queue_url
        }), 200

    except Exception as e:
        logger.error(f"Error in GetQueueUrl: {e}")
        return error_response('InternalError', str(e)), 500


def handle_list_queues():
    """Handle ListQueues action"""
    try:
        prefix = get_request_param('QueueNamePrefix')
        queue_urls = queue_manager.list_queues(prefix=prefix)

        return success_response({
            'QueueUrls': queue_urls
        }), 200

    except Exception as e:
        logger.error(f"Error in ListQueues: {e}")
        return error_response('InternalError', str(e)), 500


def handle_delete_queue():
    """Handle DeleteQueue action"""
    try:
        queue_url = get_request_param('QueueUrl')
        if not queue_url:
            return error_response('MissingParameter', 'QueueUrl is required'), 400

        # Extract queue name from URL
        queue_name = queue_url.split('/')[-1]

        success = queue_manager.delete_queue(queue_name)
        if not success:
            return error_response('QueueDoesNotExist', f'Queue does not exist'), 404

        return success_response({}), 200

    except Exception as e:
        logger.error(f"Error in DeleteQueue: {e}")
        return error_response('InternalError', str(e)), 500


def handle_send_message():
    """Handle SendMessage action"""
    try:
        queue_url = get_request_param('QueueUrl')
        message_body = get_request_param('MessageBody')

        if not queue_url:
            return error_response('MissingParameter', 'QueueUrl is required'), 400
        if not message_body:
            return error_response('MissingParameter', 'MessageBody is required'), 400

        # Extract queue name from URL
        queue_name = queue_url.split('/')[-1]

        # Extract message attributes
        message_attributes = {}
        delay_seconds = get_request_param('DelaySeconds')
        if delay_seconds:
            delay_seconds = int(delay_seconds)

        result = queue_manager.send_message(
            queue_name=queue_name,
            message_body=message_body,
            message_attributes=message_attributes,
            delay_seconds=delay_seconds
        )

        if not result:
            return error_response('QueueDoesNotExist', 'Queue does not exist'), 404

        return success_response({
            'MessageId': result.get('MessageId'),
            'MD5OfMessageBody': result.get('MD5OfMessageBody')
        }), 200

    except Exception as e:
        logger.error(f"Error in SendMessage: {e}")
        return error_response('InternalError', str(e)), 500


def handle_send_message_batch():
    """Handle SendMessageBatch action"""
    try:
        queue_url = get_request_param('QueueUrl')
        if not queue_url:
            return error_response('MissingParameter', 'QueueUrl is required'), 400

        # Extract queue name from URL
        queue_name = queue_url.split('/')[-1]

        try:
            data = json.loads(request.data)
            if 'Entries' not in data:
                raise Exception('Entries missing in request')
        except Exception as e:
            raise Exception("Missing request payload")

        # Extract batch entries
        messages = []
        entries = data.get('Entries', [])
        for entry in entries:
            messages.append({
                'Id': entry.get('Id'),
                'MessageBody': entry.get('MessageBody'),
                'DelaySeconds': entry.get('DelaySeconds', 0)
            })

        result = queue_manager.send_message_batch(queue_name, messages)

        if not result:
            return error_response('QueueDoesNotExist', 'Queue does not exist'), 404

        return success_response({
            'Successful': result.get('Successful', []),
            'Failed': result.get('Failed', [])
        }), 200

    except Exception as e:
        logger.error(f"Error in SendMessageBatch: {e}")
        return error_response('InternalError', str(e)), 500


def handle_receive_message():
    """Handle ReceiveMessage action"""
    try:
        queue_url = get_request_param('QueueUrl')
        if not queue_url:
            return error_response('MissingParameter', 'QueueUrl is required'), 400

        # Extract queue name from URL
        queue_name = queue_url.split('/')[-1]

        max_messages = int(get_request_param('MaxNumberOfMessages', 1))
        visibility_timeout = get_request_param('VisibilityTimeout')
        if visibility_timeout:
            visibility_timeout = int(visibility_timeout)
        wait_time_seconds = int(get_request_param('WaitTimeSeconds', 0))

        result = queue_manager.receive_message(
            queue_name=queue_name,
            max_messages=max_messages,
            visibility_timeout=visibility_timeout,
            wait_time_seconds=wait_time_seconds
        )

        if result is None:
            return error_response('QueueDoesNotExist', 'Queue does not exist'), 404

        return success_response({
            'Messages': result.get('Messages', [])
        }), 200

    except Exception as e:
        logger.error(f"Error in ReceiveMessage: {e}")
        return error_response('InternalError', str(e)), 500


def handle_delete_message():
    """Handle DeleteMessage action"""
    try:
        queue_url = get_request_param('QueueUrl')
        receipt_handle = get_request_param('ReceiptHandle')

        if not queue_url:
            return error_response('MissingParameter', 'QueueUrl is required'), 400
        if not receipt_handle:
            return error_response('MissingParameter', 'ReceiptHandle is required'), 400

        # Extract queue name from URL
        queue_name = queue_url.split('/')[-1]

        success = queue_manager.delete_message(queue_name, receipt_handle)

        if not success:
            return error_response('ReceiptHandleIsInvalid', 'Invalid receipt handle'), 400

        return success_response({}), 200

    except Exception as e:
        logger.error(f"Error in DeleteMessage: {e}")
        return error_response('InternalError', str(e)), 500


def handle_delete_message_batch():
    """Handle DeleteMessageBatch action"""
    try:
        queue_url = get_request_param('QueueUrl')
        if not queue_url:
            return error_response('MissingParameter', 'QueueUrl is required'), 400

        # Extract queue name from URL
        queue_name = queue_url.split('/')[-1]

        # Extract batch entries
        entries = []
        if request.is_json:
            entries = request.json.get('Entries', [])

        result = queue_manager.delete_message_batch(queue_name, entries)

        if not result:
            return error_response('QueueDoesNotExist', 'Queue does not exist'), 404

        return success_response({
            'Successful': result.get('Successful', []),
            'Failed': result.get('Failed', [])
        }), 200

    except Exception as e:
        logger.error(f"Error in DeleteMessageBatch: {e}")
        return error_response('InternalError', str(e)), 500


def handle_change_message_visibility():
    """Handle ChangeMessageVisibility action"""
    try:
        queue_url = get_request_param('QueueUrl')
        receipt_handle = get_request_param('ReceiptHandle')
        visibility_timeout = get_request_param('VisibilityTimeout')

        if not queue_url:
            return error_response('MissingParameter', 'QueueUrl is required'), 400
        if not receipt_handle:
            return error_response('MissingParameter', 'ReceiptHandle is required'), 400
        if visibility_timeout is None:
            return error_response('MissingParameter', 'VisibilityTimeout is required'), 400

        # Extract queue name from URL
        queue_name = queue_url.split('/')[-1]

        success = queue_manager.change_message_visibility(
            queue_name, receipt_handle, int(visibility_timeout)
        )

        if not success:
            return error_response('MessageNotInflight', 'Message not in flight'), 400

        return success_response({}), 200

    except Exception as e:
        logger.error(f"Error in ChangeMessageVisibility: {e}")
        return error_response('InternalError', str(e)), 500


def handle_change_message_visibility_batch():
    """Handle ChangeMessageVisibilityBatch action"""
    try:
        queue_url = get_request_param('QueueUrl')
        if not queue_url:
            return error_response('MissingParameter', 'QueueUrl is required'), 400

        # Extract queue name from URL
        queue_name = queue_url.split('/')[-1]

        # Extract batch entries
        entries = []
        if request.is_json:
            entries = request.json.get('Entries', [])

        result = queue_manager.change_message_visibility_batch(queue_name, entries)

        if not result:
            return error_response('QueueDoesNotExist', 'Queue does not exist'), 404

        return success_response({
            'Successful': result.get('Successful', []),
            'Failed': result.get('Failed', [])
        }), 200

    except Exception as e:
        logger.error(f"Error in ChangeMessageVisibilityBatch: {e}")
        return error_response('InternalError', str(e)), 500


def handle_get_queue_attributes():
    """Handle GetQueueAttributes action"""
    try:
        queue_url = get_request_param('QueueUrl')
        if not queue_url:
            return error_response('MissingParameter', 'QueueUrl is required'), 400

        # Extract queue name from URL
        queue_name = queue_url.split('/')[-1]

        # Extract attribute names
        attribute_names = get_request_param('AttributeNames') or ['All']
        if isinstance(attribute_names, str):
            attribute_names = [attribute_names]

        attributes = queue_manager.get_queue_attributes(queue_name, attribute_names)

        if attributes is None:
            return error_response('QueueDoesNotExist', 'Queue does not exist'), 404

        return success_response({
            'Attributes': attributes
        }), 200

    except Exception as e:
        logger.error(f"Error in GetQueueAttributes: {e}")
        return error_response('InternalError', str(e)), 500


def handle_set_queue_attributes():
    """Handle SetQueueAttributes action"""
    try:
        queue_url = get_request_param('QueueUrl')
        if not queue_url:
            return error_response('MissingParameter', 'QueueUrl is required'), 400

        # Extract queue name from URL
        queue_name = queue_url.split('/')[-1]

        # Extract attributes
        attributes = {}
        if request.is_json:
            attributes = request.json.get('Attributes', {})

        success = queue_manager.set_queue_attributes(queue_name, attributes)

        if not success:
            return error_response('QueueDoesNotExist', 'Queue does not exist'), 404

        return success_response({}), 200

    except Exception as e:
        logger.error(f"Error in SetQueueAttributes: {e}")
        return error_response('InternalError', str(e)), 500


def handle_purge_queue():
    """Handle PurgeQueue action"""
    try:
        queue_url = get_request_param('QueueUrl')
        if not queue_url:
            return error_response('MissingParameter', 'QueueUrl is required'), 400

        # Extract queue name from URL
        queue_name = queue_url.split('/')[-1]

        # Purge queue by calling SQS client directly
        try:
            url = queue_manager.get_queue_url(queue_name)
            if not url:
                return error_response('QueueDoesNotExist', 'Queue does not exist'), 404

            queue_manager.sqs_client.purge_queue(QueueUrl=url)
            return success_response({}), 200
        except Exception as e:
            logger.error(f"Error purging queue: {e}")
            return error_response('InternalError', str(e)), 500

    except Exception as e:
        logger.error(f"Error in PurgeQueue: {e}")
        return error_response('InternalError', str(e)), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=4566, debug=False)
