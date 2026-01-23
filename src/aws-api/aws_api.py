"""
LocalCloud - AWS API
Provides a local endpoint that handles the AWS API calls
"""
import re
from typing import Dict
import boto3
from flask import Flask, request, jsonify, Response, send_file
import requests
import json
import base64
import os
import sys
import hmac
import custom_logger
import logging
import docker
from datetime import datetime, timezone, timedelta
import zipfile
import shutil
import time
import hashlib
from pathlib import Path
from functools import wraps
import uuid
import queue
from database import Database
import sqlite3
from ssm_parameters import SSMParameterStore
import socket
from urllib.parse import urlparse, parse_qs
from botocore.config import Config
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.auth import SigV4Auth

class C:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

app = Flask(__name__)

logger = logging.getLogger(__name__)
db = Database()

# Configuration
ACCOUNT_ID = "456645664566"
REGION = "ap-southeast-2"
BACKEND_REGISTRY_HOST = os.getenv('REGISTRY_HOST', "ecr:5000")

# Database path for storing metadata about functions and their states.
DB_PATH = os.getenv("STORAGE_PATH", '/data') + '/aws_metadata.db'

# DynamoDB endpoint url
DYNAMODB_ENDPOINT = os.getenv('DYNAMODB_ENDPOINT_URL', 'http://ddb:4700')

# Endpoint for Event Source Mapping (ESM) service (runs in its own container)
ESM_ENDPOINT = os.getenv('ESM_ENDPOINT_URL', 'http://esm:4566')

# S# endpoint url - minio
S3_ENDPOINT = os.getenv('S3_ENDPOINT_URL', 'http://s3:9000')

# Lifecycle (Lambda) service endpoint
LAMBDA_ENDPOINT = os.getenv('LAMBDA_ENDPOINT_URL', 'http://lambda:4566')


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

# Storage for function code
FUNCTIONS_DIR = Path('/tmp/lambda-functions') # Yep cheating, until S3 and ECR fully supporting
FUNCTIONS_DIR.mkdir(exist_ok=True)

# Docker client
docker_client = docker.from_env()

# event_source_mapping = None
# cloudwatch_logger = None
lifecycle_manager = None
queue_manager = None
event_invoke_config = None

# Cached boto3 clients
_boto3_session = None
_sqs_client = None

def get_request_server_address():
    server = urlparse(request.base_url).hostname
    port = urlparse(request.url).port

    return server if port == 443 else f'{server}:{port}'

def esm_request(method: str, path: str, **kwargs):
    url = ESM_ENDPOINT.rstrip('/') + path
    try:
        resp = requests.request(method, url, timeout=5, **kwargs)
        # Try to return JSON when possible, else text
        try:
            return resp.status_code, resp.json()
        except Exception:
            return resp.status_code, resp.text
    except requests.exceptions.RequestException as e:
        logger.error(f"ESM request failed: {method} {url} -> {e}")
        return 502, {'message': 'ESM service unavailable'}


def esm_find_mapping_by_function(function_name: str):
    """Find an ESM mapping by function name by querying the ESM service."""
    status, data = esm_request('GET', '/2015-03-31/event-source-mappings')
    if status != 200:
        return None
    mappings = data.get('EventSourceMappings') if isinstance(data, dict) else []
    for m in mappings or []:
        if m.get('FunctionName') == function_name:
            return m
    return None


def proxy_to_sqs(operation, records):
    """Proxy S3 event records to SQS using boto3 in LocalStack"""
    # SQS endpoint for LocalStack
    SQS_ENDPOINT = os.getenv('SQS_ENDPOINT', 'http://sqs:4566')
    QUEUE_URL = os.getenv('SQS_QUEUE_URL', 'http://sqs:4566/000000000000/my-queue')  # Adjust account & queue

    # Create boto3 SQS client pointing to LocalStack
    sqs_client = boto3.client(
        'sqs',
        endpoint_url=SQS_ENDPOINT,
        region_name='us-east-1',
        aws_access_key_id='test',      # Required even in LocalStack
        aws_secret_access_key='test'
    )

    try:
        # Send each record as a message (or send all together)
        # Option: send batch if multiple records
        entries = []
        for i, record in enumerate(records):
            entries.append({
                'Id': str(i),
                'MessageBody': json.dumps(record)
            })

        if len(entries) == 1:
            # Single message
            response = sqs_client.send_message(
                QueueUrl=QUEUE_URL,
                MessageBody=json.dumps(records[0])
            )
        else:
            # Batch (up to 10)
            response = sqs_client.send_message_batch(
                QueueUrl=QUEUE_URL,
                Entries=entries
            )

        logger.debug(f"Sent to SQS: {response}")
        return {'status': 'success', 'response': response}

    except Exception as e:
        logger.error(f"Failed to send to SQS: {e}")
        return {'status': 'error', 'error': str(e)}


def dynamodb_request(method: str, path: str, **kwargs):
    """Send an HTTP request to the DynamoDB endpoint."""
    url = DYNAMODB_ENDPOINT.rstrip('/') + path
    logger.debug(f"DynamoDB request sent: {method} {url}")
    try:
        resp = requests.request(method, url, timeout=30, **kwargs)
        try:
            return resp.status_code, resp.json(), resp
        except Exception:
            return resp.status_code, resp.text, resp
    except requests.exceptions.RequestException as e:
        logger.error(f"DynamoDB request failed: {method} {url} -> {e}")
        return 502, {'message': 'DynamoDB service unavailable'}, None


def proxy_to_dynamodb(operation: str, data=None):
    """Proxy a DynamoDB API operation to the ScyllaDB service."""
    headers = {
        'X-Amz-Target': f'DynamoDB_20120810.{operation}',
        'Content-Type': 'application/x-amz-json-1.1'
    }

    # Preserve original headers if available
    for key in ['Authorization', 'X-Amz-Date', 'X-Amz-Security-Token']:
        if key in request.headers:
            headers[key] = request.headers[key]

    status, resp, raw = dynamodb_request('POST', '/', headers=headers, json=(data or {}))

    if raw is None:
        return jsonify(resp), status

    try:
        return Response(
            raw.content,
            status=raw.status_code,
            mimetype=raw.headers.get('Content-Type', 'application/x-amz-json-1.1')
        )
    except Exception:
        return jsonify(resp), status


def lambda_request(method: str, path: str, **kwargs):
    url = LAMBDA_ENDPOINT.rstrip('/') + path
    try:
        resp = requests.request(method, url, timeout=900, **kwargs)
        try:
            return resp.status_code, resp.json(), resp
        except Exception:
            return resp.status_code, resp.text, resp
    except requests.exceptions.RequestException as e:
        logger.error(f"Lambda request failed: {method} {url} -> {e}")
        return 502, {'message': 'Lambda service unavailable'}, None


def log_request(method: str, path: str = '/logs', **kwargs):
    """Send an HTTP request to the Lambda lifecycle's CloudWatch Logs endpoint."""
    url = LAMBDA_ENDPOINT.rstrip('/') + path
    logger.debug(f"Log request sent to logs: {method} {url}")
    try:
        resp = requests.request(method, url, timeout=10, **kwargs)
        try:
            return resp.status_code, resp.json(), resp
        except Exception:
            return resp.status_code, resp.text, resp
    except requests.exceptions.RequestException as e:
        logger.error(f"Log request failed: {method} {url} -> {e}")
        return 502, {'message': 'Logs service unavailable'}, None


def proxy_logs_to_lambda(operation: str, data=None):
    """Proxy a CloudWatch Logs API operation to the lambda lifecycle service."""
    headers = {
        'X-Amz-Target': f'Logs_20140328.{operation}',
        'Content-Type': 'application/x-amz-json-1.1'
    }
    status, resp, raw = log_request('POST', '/logs', headers=headers, json=(data or {}))
    if raw is None:
        return jsonify(resp), status

    try:
        return Response(raw.content, status=raw.status_code, mimetype=raw.headers.get('Content-Type', 'application/json'))
    except Exception:
        return jsonify(resp), status

def get_boto3_session():
    global _boto3_session
    if _boto3_session:
        return _boto3_session
    _boto3_session = boto3.Session(
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID', 'localcloud'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY', 'localcloud'),
        region_name=os.getenv('AWS_REGION', REGION)
    )
    return _boto3_session

def get_s3_client():
    """Return a boto3 S3 client with MinIO credentials"""
    session = get_boto3_session()
    return session.client('s3', endpoint_url=S3_ENDPOINT)

def get_sqs_client():
    """Return a cached boto3 SQS client pointed at the SQS service container."""
    global _sqs_client
    if _sqs_client:
        return _sqs_client
    session = get_boto3_session()
    # Allow overriding endpoint via env for tests
    endpoint = os.getenv('AWS_ENDPOINT_URL_SQS', 'http://sqs:4566')

    cfg = Config(retries={'max_attempts': 2})
    _sqs_client = session.client('sqs', endpoint_url=endpoint, config=cfg)
    return _sqs_client

def aws_response(operation):
    """ Decorator to format responses in AWS format """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                result = f(*args, **kwargs)
                return jsonify(result)
            except Exception as e:
                error_response = {
                    "__type": "ServiceException",
                    "message": str(e)
                }
                return jsonify(error_response), 400
        return wrapper
    return decorator

def get_request_data():
    """Get data from request, handling both JSON and form-encoded protocols"""
    content_type = request.headers.get('Content-Type', '').lower()

    # JSON protocol (application/x-amz-json-1.0)
    if 'json' in content_type or 'x-amz-json' in content_type:
        try:
            data = request.get_json(force=True)
            if data:
                return data
        except Exception as e:
            logger.error(f"Error parsing JSON: {e}")

    # Form-encoded protocol (application/x-www-form-urlencoded)
    if 'urlencoded' in content_type:
        try:
            raw_data = request.get_data(as_text=True)
            if raw_data:
                parsed = parse_qs(raw_data, keep_blank_values=True)
                # Convert lists to single values
                data = {k: v[0] if isinstance(v, list) and len(v) > 0 else v
                       for k, v in parsed.items()}
                logger.debug(f"Parsed form data: {list(data.keys())}")
                return data
        except Exception as e:
            logger.error(f"Error parsing form data: {e}")

    # Try request.form as fallback
    if request.form:
        logger.debug(f"Using request.form: {list(request.form.keys())}")
        return dict(request.form)

    # Try JSON without checking content-type (last resort)
    try:
        data = request.get_json(force=True, silent=True)
        if data:
            logger.debug(f"Parsed JSON (no content-type check): {list(data.keys())}")
            return data
    except:
        pass

    return {}

# ECR API Functions (keeping existing implementation)
# ============================================================================

# list of (pain in the ass) resource segments that follow a repository name
_RESOURCE_SEP_RE = re.compile(r'/(?:blobs|manifests|uploads|_uploads|tags|_layers|_catalog|_manifests)(?:/|$)', re.IGNORECASE)

def ecr_repository_exists(repository_name):
    if not repository_name:
        raise ValueError("repositoryName is required")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM repositories WHERE repository_name = ?', (repository_name,))
    if cursor.fetchone():
        conn.close()
        return True
        # raise ValueError(f"Repository {repository_name} already exists")
    return False

def extract_repository_from_path(path: str) -> str | None:
    """
    Given path after /v2/ (e.g. "foo/bar/blobs/uploads/..."), return repository name ("foo/bar"),
    or None if the path is registry-level or empty.
    """
    if not path:
        return None
    # strip leading/trailing slashes
    p = path.strip('/')
    # if registry-level like "_catalog", return None
    if p.startswith('_'):
        return None
    # split on the first occurrence of a known resource separator
    parts = _RESOURCE_SEP_RE.split(p, maxsplit=1)
    repo = parts[0] if parts else p
    return repo or None

def docker_registry_error(code: str, message: str, status: int = 404):
    body = {"errors": [{"code": code, "message": message, "detail": {}}]}
    return Response(json.dumps(body), status=status, mimetype="application/json")

@aws_response('CreateRepository')
def create_repository():
    """ Create a new ECR repository """
    data = get_request_data()
    logger.info(f"CreateRepository data: {data}")

    repository_name = data.get('repositoryName')

    if not repository_name:
        raise ValueError("repositoryName is required")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if ecr_repository_exists(repository_name):
        raise ValueError(f"Repository {repository_name} already exists")

    # cursor.execute('SELECT * FROM repositories WHERE repository_name = ?', (repository_name,))
    # if cursor.fetchone():
    #     conn.close()
    #     raise ValueError(f"Repository {repository_name} already exists")

    registry_host = get_request_server_address() # urlparse(request.base_url).hostname
    repository_uri = f"{registry_host}/{repository_name}"
    created_at = datetime.now(timezone.utc).isoformat()

    cursor.execute('''
        INSERT INTO repositories (repository_name, repository_uri, registry_id, created_at)
        VALUES (?, ?, ?, ?)
    ''', (repository_name, repository_uri, ACCOUNT_ID, created_at))

    conn.commit()
    conn.close()

    return {
        'repository': {
            'repositoryArn': f'arn:aws:ecr:{REGION}:{ACCOUNT_ID}:repository/{repository_name}',
            'registryId': ACCOUNT_ID,
            'repositoryName': repository_name,
            'repositoryUri': repository_uri,
            'createdAt': created_at
        }
    }

@aws_response('DescribeRepositories')
def describe_repositories():
    """ Describe ECR repositories """
    data = get_request_data() or {}
    repository_names = data.get('repositoryNames', [])

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if repository_names:
        placeholders = ','.join('?' * len(repository_names))
        cmd=f'SELECT * FROM repositories WHERE repository_name IN ({placeholders})'
        cursor.execute(cmd, repository_names)
    else:
        cursor.execute('SELECT * FROM repositories')

    rows = cursor.fetchall()
    conn.close()

    repositories = []
    for row in rows:
        repositories.append({
            'repositoryArn': f'arn:aws:ecr:{REGION}:{ACCOUNT_ID}:repository/{row[0]}',
            'registryId': row[2],
            'repositoryName': row[0],
            'repositoryUri': row[1],
            'createdAt': row[3]
        })

    return {'repositories': repositories}

@aws_response('DeleteRepository')
def delete_repository():
    """ Delete an ECR repository """
    data = get_request_data()
    repository_name = data.get('repositoryName')
    force = data.get('force', False)

    # if not ecr_repository_exists(repository_name):
    #     raise ValueError(f"Delete failed. Repository {repository_name} does not exist")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check if repository already exists
    cursor.execute('SELECT * FROM repositories WHERE repository_name = ?', (repository_name,))
    if not cursor.fetchone():
        conn.close()
        raise ValueError(f"Repository {repository_name} not found")

    # Check if repository has images
    cursor.execute('SELECT COUNT(*) FROM images WHERE repository_name = ?', (repository_name,))
    image_count = cursor.fetchone()[0]

    if image_count > 0 and not force:
        conn.close()
        raise ValueError("Repository contains images. Use force=true to delete")

    # Delete associated Docker images
    cursor.execute('SELECT docker_image_id FROM images WHERE repository_name = ?', (repository_name,))
    for row in cursor.fetchall():
        try:
            docker_client.images.remove(row[0], force=True)
        except:
            pass

    # Delete from database
    cursor.execute('DELETE FROM images WHERE repository_name = ?', (repository_name,))
    cursor.execute('DELETE FROM repositories WHERE repository_name = ?', (repository_name,))

    conn.commit()
    conn.close()

    return {
        'repository': {
            'repositoryName': repository_name,
            'registryId': ACCOUNT_ID
        }
    }

@aws_response('GetAuthorizationToken')
def get_authorization_token():
    """ Get authorization token for Docker login """
    # Generate a simple auth token
    auth_data = f"AWS:{ACCOUNT_ID}"
    auth_token = base64.b64encode(auth_data.encode()).decode()

    expires_at = datetime.now(timezone.utc) + timedelta(hours=12)
    registry_host = get_request_server_address()

    return {
        'authorizationData': [{
            'authorizationToken': auth_token,
            'expiresAt': expires_at.isoformat(),
            'proxyEndpoint': f'http://{registry_host}'
        }]
    }

@aws_response('PutImage')
def put_image():
    """Push an image to the Docker registry backend"""
    data = get_request_data()
    repository_name = data.get('repositoryName')
    image_tag = data.get('imageTag', 'latest')
    image_manifest = data.get('imageManifest')

    if not repository_name or not image_manifest:
        raise ValueError("repositoryName and imageManifest are required")

    if not ecr_repository_exists(repository_name):
        raise ValueError(f"Repository {repository_name} does not exist")

    repo_path = f"{ACCOUNT_ID}/{repository_name}"
    # registry_repo = f"{registry_host}/{repo_path}:{image_tag}"

    # Try to find local image by tag or digest
    try:
        local_image = docker_client.images.get(f"{repository_name}:{image_tag}")
        local_image.tag(f"{BACKEND_REGISTRY_HOST}/{repo_path}", tag=image_tag)
        docker_client.images.push(f"{BACKEND_REGISTRY_HOST}/{repo_path}", tag=image_tag)
    except docker.errors.ImageNotFound:
        raise ValueError(f"Local image {repository_name}:{image_tag} not found for push")

    manifest_bytes = json.dumps(image_manifest).encode() if isinstance(image_manifest, dict) else image_manifest.encode()
    image_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    pushed_at = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        '''
        INSERT OR REPLACE INTO images
        (repository_name, image_tag, image_digest, image_size, pushed_at, docker_image_id)
        VALUES (?, ?, ?, ?, ?, ?)
        ''',
        (repository_name, image_tag, image_digest, 0, pushed_at, local_image.id),
    )
    conn.commit()
    conn.close()

    return {
        'image': {
            'registryId': ACCOUNT_ID,
            'repositoryName': repository_name,
            'imageId': {'imageTag': image_tag, 'imageDigest': image_digest},
            'imageManifest': image_manifest,
        }
    }

@aws_response('ListImages')
def list_images():
    """List images in a repository - queries actual registry"""
    data = get_request_data()
    repository_name = data.get('repositoryName')

    if not ecr_repository_exists(repository_name):
        raise ValueError(f"Repository {repository_name} does not exist")

    repo_path = f"{ACCOUNT_ID}/{repository_name}"

    try:
        # Query registry for tags
        registry_url = f"http://{BACKEND_REGISTRY_HOST}/v2/{repo_path}/tags/list"
        response = requests.get(registry_url)

        if response.status_code == 404:
            # Repository exists but has no images
            return {
                'imageIds': [],
                'repositoryName': repository_name,
                'registryId': ACCOUNT_ID
            }

        if response.status_code != 200:
            raise ValueError(f"Registry returned status {response.status_code}")

        tags_data = response.json()
        tags = tags_data.get('tags') or []

        image_ids = []

        for tag in tags:
            try:
                # Get manifest to get digest
                manifest_url = f"http://{BACKEND_REGISTRY_HOST}/v2/{repo_path}/manifests/{tag}"
                manifest_response = requests.get(
                    manifest_url,
                    headers={'Accept': 'application/vnd.docker.distribution.manifest.v2+json'}
                )

                if manifest_response.status_code == 200:
                    digest = manifest_response.headers.get('Docker-Content-Digest', 'sha256:unknown')

                    image_ids.append({
                        'imageTag': tag,
                        'imageDigest': digest
                    })

            except Exception as e:
                logger.warning(f"Error getting digest for {repository_name}:{tag}: {e}")
                # Still include the tag even if we can't get the digest
                image_ids.append({
                    'imageTag': tag,
                    'imageDigest': 'sha256:unknown'
                })

        return {
            'imageIds': image_ids,
            'repositoryName': repository_name,
            'registryId': ACCOUNT_ID
        }

    except Exception as e:
        logger.error(f"Error listing images: {e}", exc_info=True)
        return {
            'imageIds': [],
            'repositoryName': repository_name,
            'registryId': ACCOUNT_ID
        }

@aws_response('BatchGetImage')
def batch_get_image():
    """Fetch image manifest from the Docker registry backend"""
    data = get_request_data()
    repository_name = data.get('repositoryName')
    image_ids = data.get('imageIds', [])
    repo_path = f"{ACCOUNT_ID}/{repository_name}"

    if not ecr_repository_exists(repository_name):
        raise ValueError(f"Repository {repository_name} does not exist")

    images, failures = [], []

    for img_id in image_ids:
        image_tag = img_id.get('imageTag', 'latest')
        full_ref = f"{BACKEND_REGISTRY_HOST}/{repo_path}:{image_tag}"
        try:
            image = docker_client.images.pull(full_ref)
            inspect = docker_client.api.inspect_image(image.id)
            digest = inspect['RepoDigests'][0].split('@')[1] if inspect.get('RepoDigests') else 'sha256:unknown'
            manifest = {
                "schemaVersion": 2,
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "config": {
                    "mediaType": "application/vnd.docker.container.image.v1+json",
                    "digest": digest,
                    "size": inspect.get('Size', 0),
                },
            }
            images.append({
                "registryId": ACCOUNT_ID,
                "repositoryName": repository_name,
                "imageId": {"imageTag": image_tag, "imageDigest": digest},
                "imageManifest": json.dumps(manifest),
            })
        except Exception as e:
            failures.append({
                "imageId": img_id,
                "failureCode": "ImageNotFound",
                "failureReason": str(e),
            })

    return {"images": images, "failures": failures}

@aws_response('DescribeImages')
def describe_images():
    """Describe images in a repository - queries actual registry"""
    data = request.get_json()
    repository_name = data.get('repositoryName')
    image_ids = data.get('imageIds', [])

    repo_path = f"{ACCOUNT_ID}/{repository_name}"

    try:
        # Get all tags for this repository from the registry
        registry_url = f"http://{BACKEND_REGISTRY_HOST}/v2/{repo_path}/tags/list"
        response = requests.get(registry_url)

        if response.status_code == 404:
            # Repository exists but has no images
            return {'imageDetails': []}

        if response.status_code != 200:
            raise ValueError(f"Registry returned status {response.status_code}")

        tags_data = response.json()
        tags = tags_data.get('tags') or []

        # If specific image IDs requested, filter to those
        if image_ids:
            requested_tags = [img.get('imageTag') for img in image_ids if 'imageTag' in img]
            if requested_tags:
                tags = [t for t in tags if t in requested_tags]

        image_details = []

        for tag in tags:
            try:
                # Get manifest for this tag to get digest and size
                manifest_url = f"http://{BACKEND_REGISTRY_HOST}/v2/{repo_path}/manifests/{tag}"
                manifest_response = requests.get(
                    manifest_url,
                    headers={'Accept': 'application/vnd.docker.distribution.manifest.v2+json'}
                )
                if manifest_response.status_code != 200:
                    continue

                # Get digest from Docker-Content-Digest header
                digest = manifest_response.headers.get('Docker-Content-Digest', 'sha256:unknown')

                manifest = manifest_response.json()
                # Calculate approximate size from layers
                size = 0
                if 'layers' in manifest:
                    for layer in manifest['layers']:
                        size += layer.get('size', 0)
                # Add config size
                if 'config' in manifest:
                    size += manifest['config'].get('size', 0)

                # Try to get pushed date from local database as fallback
                pushed_at = datetime.now(timezone.utc).isoformat()
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT pushed_at FROM images WHERE repository_name = ? AND image_tag = ?',
                    (repository_name, tag)
                )
                row = cursor.fetchone()
                conn.close()

                if row:
                    pushed_at = row[0]
                # Not sure how I ended up with duplicates, console uses root imageTags/imageDigest at least
                image_details.append({
                    'registryId': ACCOUNT_ID,
                    'repositoryName': repository_name,
                    'imageTags': [tag],
                    'imageDigest': digest,
                    'imageId': {
                        'imageTag': tag,
                        'imageDigest': digest
                    },
                    'imageSizeInBytes': size,
                    'imagePushedAt': pushed_at
                })

            except Exception as e:
                logger.warning(f"Error getting details for {repository_name}:{tag}: {e}")
                continue

        return {'imageDetails': image_details}

    except Exception as e:
        logger.error(f"Error describing images: {e}", exc_info=True)
        return {'imageDetails': []}

@aws_response('BatchDeleteImage')
def batch_delete_image():
    """ Batch delete images """
    data = request.get_json()
    repository_name = data.get('repositoryName')
    image_ids = data.get('imageIds', [])

    if not ecr_repository_exists(repository_name):
        raise ValueError(f"Repository {repository_name} does not exist")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    deleted = []
    failures = []

    for img_id in image_ids:
        image_tag = img_id.get('imageTag')
        image_digest = img_id.get('imageDigest')

        try:
            if image_tag:
                cursor.execute('SELECT docker_image_id FROM images WHERE repository_name = ? AND image_tag = ?',
                             (repository_name, image_tag))
                row = cursor.fetchone()
                if row and row[0]:
                    try:
                        docker_client.images.remove(row[0], force=True)
                    except:
                        pass

                cursor.execute('DELETE FROM images WHERE repository_name = ? AND image_tag = ?',
                             (repository_name, image_tag))
                deleted.append(img_id)
        except Exception as e:
            failures.append({
                'imageId': img_id,
                'failureCode': 'ImageNotFound',
                'failureReason': str(e)
            })

    conn.commit()
    conn.close()

    return {
        'imageIds': deleted,
        'failures': failures
    }

@app.route('/v2/', methods=['GET'])
def docker_registry_root():
    """Docker Registry v2 API root endpoint - required for docker login"""
    try:
        logger.info("Registry root endpoint hit - Docker is checking connectivity")

        # Forward to actual registry
        resp = requests.get(f"http://{BACKEND_REGISTRY_HOST}/v2/")

        return resp.content, resp.status_code, [
            ('Docker-Distribution-Api-Version', 'registry/2.0'),
            ('Content-Type', 'application/json')
        ]
    except Exception as e:
        logger.error(f"Registry root error: {e}")
        return jsonify({}), 200  # Return success anyway for docker login

@app.route('/v2/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'HEAD', 'DELETE'], strict_slashes=False)
def docker_registry_proxy(path):
    """Proxy Docker Registry v2 API calls with detailed debug logging"""
    try:
        repo = extract_repository_from_path(path)
        logger.debug(f"v2 request: path={path}, repo={repo}")
        # If it's a registry-level call (no repo) then skip repository existence check
        if repo is not None:
            # only enforce existence for APIs that require an existing repo
            if not ecr_repository_exists(repo):
                return docker_registry_error(
                    "NAME_UNKNOWN",
                    f"repository {repo} does not exist",
                    status=404
                )
        else:
            logger.critical(f"registry call only, dont think we should reach here")

        # Inject account ID namespace for isolation
        if not path.startswith(f"{ACCOUNT_ID}/"):
            path = f"{ACCOUNT_ID}/{path}"

        url = f"http://{BACKEND_REGISTRY_HOST}/v2/{path}"

        # Include query string
        if request.query_string:
            url += f"?{request.query_string.decode()}"

        # logger.info(f"=== PROXY REQUEST ===")
        # logger.info(f"Method: {request.method}")
        logger.info(f"Path: {path}")
        logger.info(f"Full URL: {url}")
        # logger.info(f"Request Headers: {dict(request.headers)}")

        # Prepare headers - exclude problematic ones
        headers = {k: v for k, v in request.headers if k.lower() not in ('host', 'content-length')}

        # Handle chunked vs regular data transfer - otherwise causes "OSError: Invalid chunk header"
        if request.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            # Stream chunked data without buffering
            logger.info("Using chunked transfer encoding")
            data = request.stream
        else:
            # For non-chunked, safe to buffer
            data = request.get_data()

        # Forward request to registry
        resp = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            data=data,
            stream=True,
            allow_redirects=False
        )

        # logger.info(f"=== REGISTRY RESPONSE ===")
        # logger.info(f"Status: {resp.status_code}")
        # logger.info(f"Response Headers: {dict(resp.headers)}")

        # Build response headers
        excluded = {'content-encoding', 'content-length', 'transfer-encoding', 'connection'}
        response_headers = []

        for k, v in resp.raw.headers.items():
            if k.lower() not in excluded:
                original_v = v

                # Rewrite Location header - a lot of effort for little reward
                if k.lower() == 'location':
                    if v.startswith('http://') or v.startswith('https://'):
                        original_host = f"http://{BACKEND_REGISTRY_HOST}"
                        proxy_host = f"http://{request.host}"
                        v = v.replace(original_host, proxy_host)
                        # Remove internal ACCOUNT_ID prefix if present
                        account_prefix = f"/v2/{ACCOUNT_ID}/"
                        if account_prefix in v:
                            v = v.replace(account_prefix, "/v2/")
                    elif v.startswith('/'):
                        # Absolute internal path → rewrite host and strip prefix
                        account_prefix = f"/v2/{ACCOUNT_ID}/"
                        v = f"http://{request.host}{v}"
                        if account_prefix in v:
                            v = v.replace(account_prefix, "/v2/")
                        logger.info(f"Rewrote Location to client path: {v}")

                response_headers.append((k, v))

        # logger.info(f"=== PROXY RESPONSE ===")
        # logger.info(f"Status: {resp.status_code}")
        # logger.info(f"Headers being sent: {response_headers}")
        # logger.info(f"==================")

        return resp.content, resp.status_code, response_headers

    except Exception as e:
        exc_type, _, tb = sys.exc_info()
        filename = tb.tb_frame.f_code.co_filename
        line_no = tb.tb_lineno
        error_details = f"{exc_type.__name__}: {e} (File \"{filename}\", line {line_no})"
        logger.error(f"Registry proxy error: {error_details}", exc_info=True)
        return jsonify({"error": f"Registry proxy error: {error_details}"}), 502

# REGISTRY_TOKENS = {} # meh
@app.route('/v2/token', methods=['GET'])
def registry_token():
    """
    Docker Registry Token Authentication
    Clients request tokens before accessing registry
    """
    service = request.args.get('service', 'registry')
    scope = request.args.get('scope', '')

    # Parse scope: repository:name:push,pull
    # For ECR-style, verify the client has permission

    # Generate a JWT-like token
    token = base64.b64encode(f"{service}:{scope}:{time.time()}".encode()).decode()


    return jsonify({
        'token': token,
        'access_token': token,
        'expires_in': 3600,
        'issued_at': datetime.now(timezone.utc).isoformat() + 'Z'
    })

@aws_response('InitiateLayerUpload')
def initiate_layer_upload():
    """Start a layer upload session"""
    data = get_request_data()
    # repository_name = data.get('repositoryName')

    upload_id = str(uuid.uuid4())

    return {
        'uploadId': upload_id,
        'partSize': 5242880  # 5MB chunks
    }

@aws_response('UploadLayerPart')
def upload_layer_part():
    """Upload a layer part (chunk of image data)"""
    data = get_request_data()
    repository_name = data.get('repositoryName')
    upload_id = data.get('uploadId')
    part_first_byte = data.get('partFirstByte', 0)
    part_last_byte = data.get('partLastByte', 0)
    layer_part_blob = str(data.get('layerPartBlob')) # base64 encoded

    if not ecr_repository_exists(repository_name):
        raise ValueError(f"Repository {repository_name} does not exist")

    # Store part temporarily
    upload_dir = Path(f'{FUNCTIONS_DIR}/uploads/{upload_id}')
    upload_dir.mkdir(parents=True, exist_ok=True)

    part_file = upload_dir / f"part_{part_first_byte}_{part_last_byte}"
    part_file.write_bytes(base64.b64decode(layer_part_blob))

    return {
        'registryId': ACCOUNT_ID,
        'repositoryName': repository_name,
        'uploadId': upload_id,
        'lastByteReceived': part_last_byte
    }

@aws_response('CompleteLayerUpload')
def complete_layer_upload():
    """Complete layer upload and push to registry"""
    data = get_request_data()
    repository_name = data.get('repositoryName')
    upload_id = data.get('uploadId')
    layer_digests = data.get('layerDigests', [])

    if not ecr_repository_exists(repository_name):
        raise ValueError(f"Repository {repository_name} does not exist")

    upload_dir = Path(f'{FUNCTIONS_DIR}/uploads/{upload_id}')

    # Combine all parts
    combined_data = b''
    for part_file in sorted(upload_dir.glob('part_*')):
        combined_data += part_file.read_bytes()

    # Calculate digest
    digest = "sha256:" + hashlib.sha256(combined_data).hexdigest()

    # Push to registry using Docker API
    repo_path = f"{ACCOUNT_ID}/{repository_name}"

    # Save as temporary image and push
    temp_image_path = upload_dir / 'image.tar'
    temp_image_path.write_bytes(combined_data)

    # Load image into Docker
    with open(temp_image_path, 'rb') as f:
        image = docker_client.images.load(f.read())[0]

    # Tag and push to local registry
    image.tag(f"{BACKEND_REGISTRY_HOST}/{repo_path}", tag='latest')
    docker_client.images.push(f"{BACKEND_REGISTRY_HOST}/{repo_path}", tag='latest')

    # Cleanup
    shutil.rmtree(upload_dir)

    return {
        'registryId': ACCOUNT_ID,
        'repositoryName': repository_name,
        'uploadId': upload_id,
        'layerDigest': digest
    }

@aws_response('PutImage')
def put_image():
    """Push an image to the Docker registry backend"""
    data = get_request_data()
    repository_name = data.get('repositoryName')
    image_tag = data.get('imageTag', 'latest')
    image_manifest = data.get('imageManifest')

    if not repository_name or not image_manifest:
        raise ValueError("repositoryName and imageManifest are required")

    if not ecr_repository_exists(repository_name):
        raise ValueError(f"Repository {repository_name} does not exist")

    repo_path = f"{ACCOUNT_ID}/{repository_name}"

    # Try to find local image by tag or digest
    try:
        local_image = docker_client.images.get(f"{repository_name}:{image_tag}")
        local_image.tag(f"{BACKEND_REGISTRY_HOST}/{repo_path}", tag=image_tag)
        docker_client.images.push(f"{BACKEND_REGISTRY_HOST}/{repo_path}", tag=image_tag)
    except docker.errors.ImageNotFound:
        raise ValueError(f"Local image {repository_name}:{image_tag} not found for push")

    # Get actual digest from registry after push
    try:
        manifest_url = f"http://{BACKEND_REGISTRY_HOST}/v2/{repo_path}/manifests/{image_tag}"
        manifest_response = requests.get(
            manifest_url,
            headers={'Accept': 'application/vnd.docker.distribution.manifest.v2+json'}
        )
        image_digest = manifest_response.headers.get('Docker-Content-Digest', 'sha256:unknown')
    except Exception as e:
        logger.warning(f"Could not get digest from registry: {e}")
        # Fallback to calculating from manifest
        manifest_bytes = json.dumps(image_manifest).encode() if isinstance(image_manifest, dict) else image_manifest.encode()
        image_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()

    pushed_at = datetime.now(timezone.utc).isoformat()

    # Update database for tracking (optional, since we now query registry directly)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        '''
        INSERT OR REPLACE INTO images
        (repository_name, image_tag, image_digest, image_size, pushed_at, docker_image_id)
        VALUES (?, ?, ?, ?, ?, ?)
        ''',
        (repository_name, image_tag, image_digest, 0, pushed_at, local_image.id),
    )
    conn.commit()
    conn.close()

    return {
        'image': {
            'registryId': ACCOUNT_ID,
            'repositoryName': repository_name,
            'imageId': {'imageTag': image_tag, 'imageDigest': image_digest},
            'imageManifest': image_manifest,
        }
    }

@aws_response('BatchGetImage')
def batch_get_image_enhanced():
    """
    Enhanced BatchGetImage - returns image data that can be loaded
    """
    data = get_request_data()
    repository_name = data.get('repositoryName')
    image_ids = data.get('imageIds', [])
    include_image_data = data.get('includeImageData', False)
    registry_host = get_request_server_address()

    if not ecr_repository_exists(repository_name):
        raise ValueError(f"Repository {repository_name} does not exist")

    repo_path = f"{ACCOUNT_ID}/{repository_name}"
    images, failures = [], []

    for img_id in image_ids:
        image_tag = img_id.get('imageTag', 'latest')
        full_ref = f"{registry_host}/{repo_path}:{image_tag}"

        try:
            # Pull from registry
            image = docker_client.images.pull(full_ref)
            inspect = docker_client.api.inspect_image(image.id)
            digest = inspect['RepoDigests'][0].split('@')[1] if inspect.get('RepoDigests') else 'sha256:unknown'

            result = {
                "registryId": ACCOUNT_ID,
                "repositoryName": repository_name,
                "imageId": {"imageTag": image_tag, "imageDigest": digest},
                "imageManifest": json.dumps({
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                    "config": {
                        "mediaType": "application/vnd.docker.container.image.v1+json",
                        "digest": digest,
                        "size": inspect.get('Size', 0),
                    }
                })
            }

            # Optionally include full image data
            if include_image_data:
                # Export image as tar
                image_data = image.save()
                result['imageData'] = base64.b64encode(b''.join(image_data)).decode()

            images.append(result)

        except Exception as e:
            failures.append({
                "imageId": img_id,
                "failureCode": "ImageNotFound",
                "failureReason": str(e),
            })

    return {"images": images, "failures": failures}

# S3 API Functions
@aws_response('ListBuckets')
def list_buckets():
    return proxy_to_s3()

# SigV4 Authentication (LocalStack-style)
class SigV4Validator:
    """AWS Signature Version 4 validator (LocalStack-style)"""

    def __init__(self, skip_validation=True, access_key='test', secret_key='test',
                 region='us-east-1', service='lambda'):
        self.skip_validation = skip_validation
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.service = service

    def validate_request(self, request):
        """Validate the SigV4 signature in the request (LocalStack-style)"""

        # If signature validation is disabled, accept all requests
        if self.skip_validation:
            logger.debug("Signature validation skipped")
            return True, "Validation skipped"

        auth_header = request.headers.get('Authorization', '')

        if not auth_header.startswith('AWS4-HMAC-SHA256'):
            # No auth header - accept if validation is disabled
            logger.warning("No Authorization header found")
            return self.skip_validation, "Missing Authorization header"

        # Parse authorization header
        try:
            parts = auth_header.split(' ', 1)[1].split(', ')
            credential = None
            signed_headers = None
            signature = None

            for part in parts:
                if part.startswith('Credential='):
                    credential = part.split('=', 1)[1]
                elif part.startswith('SignedHeaders='):
                    signed_headers = part.split('=', 1)[1]
                elif part.startswith('Signature='):
                    signature = part.split('=', 1)[1]

            if not all([credential, signed_headers, signature]):
                return False, "Incomplete authorization header"

            # Extract access key and date from credential
            cred_parts = credential.split('/')
            request_access_key = cred_parts[0]
            date_stamp = cred_parts[1]

            # Verify access key matches
            if request_access_key != self.access_key:
                return False, "Invalid access key"

            # Calculate expected signature
            expected_sig = self._calculate_signature(
                request, date_stamp, signed_headers
            )

            # Compare signatures
            if signature == expected_sig:
                return True, "Valid signature"
            else:
                logger.warning(f"Signature mismatch. Expected: {expected_sig}, Got: {signature}")
                # In LocalStack mode, log warning but don't reject
                if self.skip_validation:
                    logger.warning("Signatures do not match, but accepting due to skip_validation=True")
                    return True, "Signature mismatch accepted"
                return False, "Invalid signature"

        except Exception as e:
            logger.error(f"Error validating signature: {e}")
            return False, f"Signature validation error: {str(e)}"

    def _calculate_signature(self, request, date_stamp, signed_headers):
        """Calculate the expected AWS SigV4 signature"""

        # Get request body
        payload = request.get_data()
        payload_hash = hashlib.sha256(payload).hexdigest()

        # Build canonical request
        canonical_uri = request.path
        canonical_querystring = ''

        # Build canonical headers
        header_list = signed_headers.split(';')
        canonical_headers = ''
        for header in header_list:
            value = request.headers.get(header, '').strip()
            canonical_headers += f"{header}:{value}\n"

        # Build canonical request
        canonical_request = '\n'.join([
            request.method,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash
        ])

        # Create string to sign
        algorithm = 'AWS4-HMAC-SHA256'
        amz_date = request.headers.get('X-Amz-Date', '')
        credential_scope = f"{date_stamp}/{self.region}/{self.service}/aws4_request"

        string_to_sign = '\n'.join([
            algorithm,
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode()).hexdigest()
        ])

        # Calculate signature
        signing_key = self._get_signature_key(date_stamp)
        signature = hmac.new(
            signing_key,
            string_to_sign.encode(),
            hashlib.sha256
        ).hexdigest()

        return signature

    def _get_signature_key(self, date_stamp):
        """Derive the signing key"""
        k_date = hmac.new(
            f"AWS4{self.secret_key}".encode(),
            date_stamp.encode(),
            hashlib.sha256
        ).digest()
        k_region = hmac.new(k_date, self.region.encode(), hashlib.sha256).digest()
        k_service = hmac.new(k_region, self.service.encode(), hashlib.sha256).digest()
        k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
        return k_signing

def require_sigv4(validator):
    """Decorator to require SigV4 authentication"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            is_valid, message = validator.validate_request(request)
            if not is_valid:
                logger.warning(f"Authentication failed: {message}")
                return jsonify({
                    'errorMessage': 'Authentication failed',
                    'errorType': 'UnrecognizedClientException'
                }), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Initialize SigV4 validator (LocalStack-style)
# Set skip_validation=True to accept any credentials (like LocalStack does by default)
# Set skip_validation=False to enforce test/test credentials
sigv4_validator = SigV4Validator(
    skip_validation=os.getenv('LAMBDA_SKIP_SIGNATURE_VALIDATION', '1') == '1',
    access_key='test',
    secret_key='test',
    region='us-east-1',
    service='lambda'
)

def find_available_port():
    """Find an available port for Lambda container"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port

# TODO should be moved into container lifecycle
def wait_for_container_ready(container, timeout=30):
    """Wait for container to be running and polling for invocations"""
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            container.reload()
            if container.status == 'exited':
                return False
            if container.status == 'running':
                # Give it a moment to start polling
                time.sleep(2)
                return True
        except Exception as e:
            logger.error(f"Error checking container status: {e}")
            return False

        time.sleep(0.5)

    return False

# TODO should be moved into container lifecycle
def get_function_containers(function_name, status='running'):
    """Get all containers for a function"""
    filters = {
        'label': [
            'localcloud=true',
            f'function-name={function_name}'
        ]
    }

    if status:
        filters['status'] = status

    try:
        return docker_client.containers.list(all=(status is None), filters=filters)
    except Exception as e:
        logger.error(f"Error listing containers: {e}", exc_info=True)
        return []

# TODO should be moved into container lifecycle
def get_function_name_from_container(container):
    """Extract function name from container labels"""
    return container.labels.get('function-name')

@app.before_request
def logging_request():
    """
    Log incoming requests
    """
    if request.path != '/health':
        logger.debug(f"Request: {request.method} {request.path} from {request.remote_addr}, Headers: {dict(request.headers)}")

@app.route('/2018-06-01/runtime/invocation/next', methods=['GET'])
def runtime_next_invocation():
    """
    Lambda Runtime API - Container polls this for next invocation
    """
    # Proxy the runtime "next" request to the Lambda lifecycle service
    client_ip = request.remote_addr
    headers = dict(request.headers)
    headers['X-Forwarded-For'] = client_ip
    status, data, raw = lambda_request('GET', '/2018-06-01/runtime/invocation/next', headers=headers)
    if status == 200:
        # {
        # 'Lambda-Runtime-Aws-Request-Id': request_id,
        # 'Lambda-Runtime-Invoked-Function-Arn': f'arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:{function_name}',
        # 'Lambda-Runtime-Deadline-Ms': str(int(time.time() * 1000) + 60000)
        # }
        logger.info(f"Lambda response received: {status}:{raw}")
        return Response(raw.content, status=200, mimetype=raw.headers.get('Content-Type', 'text/plain'),
                        headers=raw.headers.get('lambda-runtime-aws-request-id'))
    if status == 204:
        return Response('', status=204, mimetype=raw.headers.get('Content-Type', 'text/plain'),
                        headers=raw.headers.get('lambda-runtime-aws-request-id'))
    return (status, 500)

@app.route('/2018-06-01/runtime/invocation/<request_id>/response', methods=['POST'])
def runtime_invocation_response(request_id):
    """Lambda Runtime API - Container sends response here"""
    # Proxy the runtime response to the Lambda lifecycle service
    response_data = request.get_data()
    client_ip = request.remote_addr
    headers = dict(request.headers)
    headers['X-Forwarded-For'] = client_ip
    status, _, raw = lambda_request('POST', f'/2018-06-01/runtime/invocation/{request_id}/response', headers=headers, data=response_data)
    if status in (200, 202, 204):
        return Response('', status=202, mimetype=raw.headers.get('Content-Type', 'text/plain'),
                        headers=raw.headers.get('lambda-runtime-aws-request-id'))
    return ('', 500)

@app.route('/2018-06-01/runtime/invocation/<request_id>/error', methods=['POST'])
def runtime_invocation_error(request_id):
    """
    Lambda Runtime API - Container sends errors here
    """
    # Proxy runtime error to Lambda lifecycle service
    error_data = request.get_data()
    headers = dict(request.headers)
    status, _, raw = lambda_request('POST', f'/2018-06-01/runtime/invocation/{request_id}/error', headers=headers, data=error_data)
    if status in (200, 202, 204):
        return Response('', status=202, mimetype=raw.headers.get('Content-Type', 'text/plain'),
                        headers=raw.headers.get('lambda-runtime-aws-request-id'))
    return '', 500

@app.route('/2018-06-01/runtime/init/error', methods=['POST'])
def runtime_init_error():
    """Lambda Runtime API - Container sends initialization errors"""
    # Proxy runtime error to Lambda lifecycle service
    error_data = request.get_data()
    headers = dict(request.headers)
    status, body, raw = lambda_request('POST', f'/2018-06-01/runtime/init/error', headers=headers, data=error_data)
    return Response(body, status=status, mimetype=raw.headers.get('Content-Type', 'text/plain'),
                    headers=raw.headers.get('lambda-runtime-aws-request-id'))


@app.route('/2015-03-31/functions', methods=['POST'], strict_slashes=False)
def create_function():
    """Create a new Lambda function with multi-runtime support - proxy to lambda endpoint"""
    try:
        data = request.get_json() or {}
        function_name = data.get('FunctionName')

        if not function_name:
            logger.error(f"InvalidParameterValueException: FunctionName is required")
            return jsonify({
                'errorMessage': 'FunctionName is required',
                'errorType': 'InvalidParameterValueException'
            }), 400

        logger.info(f"Creating function [{function_name}]")

        # Proxy creation request to lambda service endpoint
        status, resp, raw = lambda_request('POST', '/2015-03-31/functions', json=data)

        if status >= 400:
            # Forward error from lambda service
            logger.warning(f"Lambda service returned error: {status} - {resp}")
            return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

        # Save to local database for reference
        created = resp if isinstance(resp, dict) else {}
        function_config = {
            'FunctionName': function_name,
            'FunctionArn': created.get('FunctionArn', f'arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:{function_name}'),
            'Runtime': created.get('Runtime', data.get('Runtime', 'python3.11')),
            'Handler': created.get('Handler', data.get('Handler', 'lambda_function.handler')),
            'Role': created.get('Role', data.get('Role', f'arn:aws:iam::{ACCOUNT_ID}:role/lambda-role')),
            'CodeSize': created.get('CodeSize', 0),
            'State': created.get('State', 'Active'),
            'LastUpdateStatus': created.get('LastUpdateStatus', 'Successful'),
            'PackageType': created.get('PackageType', 'Zip'),
            'CodeSha256': created.get('CodeSha256'),
            'Environment': created.get('Environment', data.get('Environment', {}).get('Variables', {})),
            'LoggingConfig': created.get('LoggingConfig', data.get('LoggingConfig', {}))
        }

        db.save_function_to_db(function_config)
        logger.info(f"Function created successfully: {function_name}")

        # Return response from lambda service
        return jsonify(resp), status

    except Exception as e:
        exc_type, _, tb = sys.exc_info()
        filename = tb.tb_frame.f_code.co_filename
        line_no = tb.tb_lineno
        error_details = f"{exc_type.__name__}: {e} (File \"{filename}\", line {line_no})"
        logger.error(f"Unhandled exception: {error_details}", exc_info=True)
        error_response = {
            "__type": "ServiceException:",
            "message": f"Unhandled exception: {error_details}"
        }
        return error_response, 500

@app.route('/2015-03-31/functions/<function_name>', methods=['DELETE'], strict_slashes=False)
def delete_function(function_name):
    """Delete a Lambda function - proxy to lambda endpoint"""
    try:
        logger.info(f"Function delete request: {function_name}")

        # Proxy to lambda service endpoint
        status, resp, raw = lambda_request('DELETE', f'/2015-03-31/functions/{function_name}')

        if status >= 400:
            logger.warning(f"Lambda service returned error: {status} - {resp}")
            return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

        # Remove from local database after successful deletion
        db.delete_function_from_db(function_name)
        logger.info(f"Function deleted: {function_name}")

        return '', 204

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

@app.route('/2015-03-31/functions/<function_name>/code', methods=['PUT'], strict_slashes=False)
def update_function_code(function_name):
    """Update function code - proxy to lambda endpoint"""
    try:
        logger.info(f"Updating function code: {function_name}")

        data = request.get_json() or {}

        # Proxy to lambda service endpoint
        status, resp, raw = lambda_request('PUT', f'/2015-03-31/functions/{function_name}/code', json=data)

        if status >= 400:
            logger.warning(f"Lambda service returned error: {status} - {resp}")
            return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

        logger.info(f"Function code updated: {function_name}")
        return jsonify(resp), status

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

@app.route('/2015-03-31/functions/<function_name>/configuration', methods=['GET'], strict_slashes=False)
def get_function_configuration(function_name):
    """Get Lambda function configuration - proxy to lambda endpoint"""
    try:
        logger.info(f"Getting function configuration: {function_name}")

        # Proxy to lambda service endpoint
        status, resp, raw = lambda_request('GET', f'/2015-03-31/functions/{function_name}/configuration')

        if status >= 400:
            logger.warning(f"Lambda service returned error: {status} - {resp}")
            return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

        return jsonify(resp), status

    except Exception as e:
        logger.error(f"Error getting configuration for {function_name}: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": f"Unhandled exception for function: {function_name} - {e}"
        }), 500

@app.route('/2015-03-31/functions/<function_name>/configuration', methods=['PUT'], strict_slashes=False)
def update_function_configuration(function_name):
    """Update Lambda function configuration - proxy to lambda endpoint"""
    try:
        logger.info(f"Updating function configuration: {function_name}")

        data = request.get_json() or {}

        # Proxy to lambda service endpoint
        status, resp, raw = lambda_request('PUT', f'/2015-03-31/functions/{function_name}/configuration', json=data)

        if status >= 400:
            logger.warning(f"Lambda service returned error: {status} - {resp}")
            return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

        logger.info(f"Function configuration updated: {function_name}")
        return jsonify(resp), status

    except Exception as e:
        logger.error(f"Error updating configuration for {function_name}: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": f"Unhandled exception for function: {function_name} - {e}"
        }), 500

# S3 Webhook
@app.route('/webhook/sqs', methods=['POST'])
def webhook_s3():
    """Single webhook receives ALL S3 events, routes to matching queues"""
    try:
        event_data = request.get_json()
        logger.info(f'S3 Webhook received: {json.dumps(event_data)}')

        for record in event_data.get('Records', []):
            bucket_name = record['s3']['bucket']['name']
            event_name = record['eventName']  # e.g., 's3:ObjectCreated:Put'
            object_key = record['s3']['object']['key']

            # Get ALL notification configs for this bucket
            configs = db.get_bucket_notification_configs(bucket_name)

            if not configs:
                logger.warning(f"No notification configs found for bucket {bucket_name}")
                continue

            # Find which configs match this event
            matched_queues = []
            for config in configs:
                if event_matches_config(event_name, object_key, config):
                    matched_queues.append(config['queue_url'])
                    send_event_to_queue(config['queue_url'], record)
                    logger.info(f"Routed {event_name} on {object_key} to queue {config['queue_url']}")

            if not matched_queues:
                logger.warning(f"Event {event_name} on {object_key} matched no notification configs")

        return '', 200
    except Exception as e:
        logger.error(f"Webhook error: {e}", exc_info=True)
        return '', 500

def event_matches_config(event_name, object_key, config):
    """Check if S3 event matches notification configuration"""
    # Parse event patterns from config
    event_patterns = config.get('event_patterns')
    if isinstance(event_patterns, str):
        event_patterns = json.loads(event_patterns)

    # Check if event type matches any pattern
    event_match = False
    for pattern in event_patterns:
        if pattern.endswith('*'):
            # Wildcard match: "s3:ObjectCreated:*" matches "s3:ObjectCreated:Put"
            prefix = pattern[:-1]
            if event_name.startswith(prefix):
                event_match = True
                break
        elif pattern == event_name:
            # Exact match
            event_match = True
            break

    if not event_match:
        logger.debug(f"Event {event_name} doesn't match patterns {event_patterns}")
        return False

    # Check filter rules (prefix/suffix) if present
    filter_rules = config.get('filter_rules')
    if filter_rules:
        if isinstance(filter_rules, str):
            filter_rules = json.loads(filter_rules)

        for rule in filter_rules:
            name = rule.get('Name', '').lower()
            value = rule.get('Value', '')

            if name == 'prefix' and not object_key.startswith(value):
                logger.debug(f"Object key {object_key} doesn't match prefix {value}")
                return False
            if name == 'suffix' and not object_key.endswith(value):
                logger.debug(f"Object key {object_key} doesn't match suffix {value}")
                return False

    return True

def send_event_to_queue(queue_url, record):
    """Send S3 event record to SQS queue"""
    try:
        sqs_client = get_sqs_client()

        # Wrap single record in Records array (AWS S3 event format)
        message_body = json.dumps({'Records': [record]})

        response = sqs_client.send_message(
            QueueUrl=queue_url,
            MessageBody=message_body
        )

        logger.debug(f"Sent message to {queue_url}: {response.get('MessageId')}")
        return response

    except Exception as e:
        logger.error(f"Failed to send event to queue {queue_url}: {e}", exc_info=True)
        raise

# DDB debug endpoint
@app.route('/debug/dynamodb-status', methods=['GET'])
def dynamodb_status():
    """Get DynamoDB (ScyllaDB) service status"""
    try:
        # Try a simple ListTables to check connectivity
        status, resp, raw = dynamodb_request('POST', '/',
            headers={
                'X-Amz-Target': 'DynamoDB_20120810.ListTables',
                'Content-Type': 'application/x-amz-json-1.1'
            },
            json={}
        )

        if status == 200:
            return jsonify({
                'status': 'healthy',
                'endpoint': DYNAMODB_ENDPOINT,
                'response': resp
            }), 200
        else:
            return jsonify({
                'status': 'unhealthy',
                'endpoint': DYNAMODB_ENDPOINT,
                'error': resp
            }), 503

    except Exception as e:
        logger.error(f"Failed to check DynamoDB status: {e}", exc_info=True)
        return jsonify({
            'status': 'unavailable',
            'endpoint': DYNAMODB_ENDPOINT,
            'error': str(e)
        }), 503

# ESM debug endpoint
@app.route('/debug/esm-status', methods=['GET'])
def esm_status():
    status_code, data = esm_request('GET', '/internal/esm/status')
    if status_code == 200:
        return jsonify(data), 200
    return jsonify({'message': 'ESM status unavailable'}), 502

# Lambda debug endpoint
@app.route('/debug/lambda-status', methods=['GET'])
def lambda_status():
    status, resp, raw = lambda_request('GET', '/debug/lambda-status')
    if status == 200:
        return jsonify(resp), 200
    return jsonify({'message': 'Lambda lifecycle status unavailable'}), 502

# SQS debug endpoint
@app.route('/debug/sqs-status', methods=['GET'])
def sqs_status():
    # The SQS service now runs in a separate container. Proxy the debug status
    # request to the SQS container so the API gateway can return status even
    # when `queue_manager` is not initialized in this process.
    aws_sqs_url = os.getenv('AWS_ENDPOINT_URL_SQS', 'http://sqs:4566')
    try:
        resp = requests.get(f"{aws_sqs_url}/debug/sqs-status", timeout=5)
        # Forward the SQS container response (assume JSON)
        return Response(resp.content, status=resp.status_code, mimetype=resp.headers.get('Content-Type', 'application/json'))
    except Exception as e:
        logger.error(f"Failed to fetch SQS status from {aws_sqs_url}: {e}", exc_info=True)
        return jsonify({"error": "SQS status unavailable", "message": str(e)}), 503

@app.route('/2019-09-25/functions/<function_name>/event-invoke-config', methods=['GET'], strict_slashes=False)
def get_function_event_invoke_config_endpoint(function_name):
    """Get function event invoke configuration - proxy to lambda endpoint"""
    try:
        logger.info(f"Getting event invoke config for: {function_name}")

        # Preserve query parameters
        query_string = request.query_string.decode() if request.query_string else ''
        path = f'/2019-09-25/functions/{function_name}/event-invoke-config'
        if query_string:
            path = f'{path}?{query_string}'

        # Proxy to lambda service endpoint
        status, resp, raw = lambda_request('GET', path)

        if status >= 400:
            logger.warning(f"Lambda service returned error: {status} - {resp}")
            return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

        return jsonify(resp), status

    except Exception as e:
        logger.error(f"Error getting event invoke config: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500

@app.route('/2019-09-25/functions/<function_name>/event-invoke-config', methods=['PUT'], strict_slashes=False)
def put_function_event_invoke_config_endpoint(function_name):
    """Create or update event invoke configuration - proxy to lambda endpoint"""
    try:
        logger.info(f"Setting event invoke config for: {function_name}")

        data = request.get_json() or {}

        # Preserve query parameters
        query_string = request.query_string.decode() if request.query_string else ''
        path = f'/2019-09-25/functions/{function_name}/event-invoke-config'
        if query_string:
            path = f'{path}?{query_string}'

        # Proxy to lambda service endpoint
        status, resp, raw = lambda_request('PUT', path, json=data)

        if status >= 400:
            logger.warning(f"Lambda service returned error: {status} - {resp}")
            return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

        return jsonify(resp), status

    except Exception as e:
        logger.error(f"Error putting event invoke config: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500

@app.route('/2019-09-25/functions/<function_name>/event-invoke-config', methods=['POST'], strict_slashes=False)
def update_function_event_invoke_config_endpoint(function_name):
    """Update event invoke configuration - proxy to lambda endpoint"""
    try:
        logger.info(f"Updating event invoke config for: {function_name}")

        data = request.get_json() or {}

        # Preserve query parameters
        query_string = request.query_string.decode() if request.query_string else ''
        path = f'/2019-09-25/functions/{function_name}/event-invoke-config'
        if query_string:
            path = f'{path}?{query_string}'

        # Proxy to lambda service endpoint
        status, resp, raw = lambda_request('POST', path, json=data)

        if status >= 400:
            logger.warning(f"Lambda service returned error: {status} - {resp}")
            return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

        return jsonify(resp), status

    except Exception as e:
        logger.error(f"Error updating event invoke config: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500

@app.route('/2019-09-25/functions/<function_name>/event-invoke-config', methods=['DELETE'], strict_slashes=False)
def delete_function_event_invoke_config_endpoint(function_name):
    """Delete event invoke configuration - proxy to lambda endpoint"""
    try:
        logger.info(f"Deleting event invoke config for: {function_name}")

        # Preserve query parameters
        query_string = request.query_string.decode() if request.query_string else ''
        path = f'/2019-09-25/functions/{function_name}/event-invoke-config'
        if query_string:
            path = f'{path}?{query_string}'

        # Proxy to lambda service endpoint
        status, resp, raw = lambda_request('DELETE', path)

        if status >= 400:
            logger.warning(f"Lambda service returned error: {status} - {resp}")
            return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

        return '', 204

    except Exception as e:
        logger.error(f"Error deleting event invoke config: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500

@app.route('/test', methods=['GET'])
def test_containers():
    containers = docker_client.containers.list(all=True, filters={"name": "localcloud-my-function"})
    return jsonify([c.name for c in containers])

# Removed @require_sigv4 decorator for now to simplify debugging
@app.route('/2015-03-31/functions/<function_name>/invocations', methods=['POST'])
@app.route('/2015-03-31/functions/<path:function_name>/invocations', methods=['POST'])
def invoke_function(function_name):
    """AWS Lambda Invoke API endpoint - proxy to lambda endpoint"""
    logger.info(f"Invoking function request for Function:{function_name}")

    # Validate signature (permissive for local testing)
    try:
        is_valid, message = sigv4_validator.validate_request(request)
        if not is_valid:
            logger.warning(f"Authentication failed: {message}")
    except Exception as e:
        logger.warning(f"Auth validation error: {e}")

    # Get payload
    raw_payload = request.get_data()

    logger.debug(f"Raw payload type: {type(raw_payload)}")
    logger.debug(f"Raw payload length: {len(raw_payload) if raw_payload else 0}")

    # Proxy invocation to the Lambda service endpoint
    headers = dict(request.headers)
    # Remove Host to avoid confusing target service
    headers.pop('Host', None)

    # ESM invocations have 905s timeout, so we need to match or exceed that
    try:
        status, resp, raw = lambda_request('POST', f'/2015-03-31/functions/{function_name}/invocations',
            headers=headers,
            data=raw_payload
        )

        if raw is None:
            logger.error(f"No response received from lambda service for {function_name}")
            return jsonify({
                '__type': 'ServiceException',
                'message': 'Lambda service did not return a response'
            }), 502

        # Get the response content type
        content_type = raw.headers.get('Content-Type', 'application/json')

        # Build response headers from Lambda service
        response_headers = {}
        for k, v in raw.headers.items():
            response_headers[k] = v

        logger.info(f"Returning response for {function_name}: status={status}, content_type={content_type}")

        # Return the response exactly as received from lambda service
        return Response(
            raw.content,
            status=status,
            headers=response_headers,
            mimetype=content_type
        )

    except requests.exceptions.Timeout as e:
        logger.error(f"Timeout waiting for lambda service response: {e}")
        return jsonify({
            '__type': 'TimeoutError',
            'message': f'Lambda service timed out after waiting for response'
        }), 504
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection error to lambda service: {e}")
        return jsonify({
            '__type': 'ServiceUnavailableException',
            'message': 'Lambda service unavailable'
        }), 503
    except Exception as e:
        logger.error(f"Unexpected error proxying to lambda service: {e}", exc_info=True)
        return jsonify({
            '__type': 'ServiceException',
            'message': str(e)
        }), 500

@app.route('/2015-03-31/functions/<function_name>/provisioned-concurrency-configs', methods=['PUT'])
def put_provisioned_concurrency(function_name):
    """Set provisioned concurrency for a function - proxy to lambda endpoint"""
    try:
        logger.info(f"Setting provisioned concurrency for: {function_name}")

        data = request.get_json() or {}

        # Proxy to lambda service endpoint
        status, resp, raw = lambda_request('PUT', f'/2015-03-31/functions/{function_name}/provisioned-concurrency-configs', json=data)

        if status >= 400:
            logger.warning(f"Lambda service returned error: {status} - {resp}")
            return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

        return jsonify(resp), status

    except Exception as e:
        logger.error(f"Error setting provisioned concurrency: {e}", exc_info=True)
        return jsonify({
            'message': f"Unhandled exception setting provisioned concurrency: {e}",
            '__type': 'ServiceException'
        }), 500

@app.route('/2015-03-31/functions/<function_name>/concurrency', methods=['PUT'])
def put_function_concurrency(function_name):
    """Set reserved concurrent executions for a function - proxy to lambda endpoint"""
    try:
        logger.info(f"Setting reserved concurrency for: {function_name}")

        data = request.get_json() or {}

        # Proxy to lambda service endpoint
        status, resp, raw = lambda_request('PUT', f'/2015-03-31/functions/{function_name}/concurrency', json=data)

        if status >= 400:
            logger.warning(f"Lambda service returned error: {status} - {resp}")
            return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

        return jsonify(resp), status

    except Exception as e:
        logger.error(f"Error setting concurrency for {function_name}: {e}", exc_info=True)
        error_response = {
            "__type": "ServiceException:",
            "message": str(e)
        }
        return error_response, 500

# Test endpoint to verify routing
@app.route('/test/invoke/<function_name>', methods=['POST', 'GET'])
def test_invoke(function_name):
    """Test endpoint to verify routing works"""
    return jsonify({
        'message': f'Test route working for function: {function_name}',
        'method': request.method,
        'path': request.path
    })

@app.route('/2015-03-31/functions/<function_name>', methods=['GET'], strict_slashes=False)
def get_function(function_name):
    """Get function configuration - proxy to lambda endpoint"""
    try:
        # Proxy to lambda service endpoint
        status, resp, raw = lambda_request('GET', f'/2015-03-31/functions/{function_name}')

        if status >= 400:
            logger.warning(f"Lambda service returned error: {status} - {resp}")
            return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

        return jsonify(resp), status

    except Exception as e:
        logger.error(f"Error getting function {function_name}: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": f"Unhandled exception for function: {function_name} - {e}"
        }), 500

@app.route('/2015-03-31/functions', methods=['GET'], strict_slashes=False)
def list_functions():
    """List all available functions - proxy to lambda endpoint"""
    try:
        logger.info(f'Lambda request - list-functions')

        # Proxy to lambda service endpoint
        status, resp, raw = lambda_request('GET', f'/2015-03-31/functions')

        if status >= 400:
            logger.warning(f"Lambda service returned error: {status} - {resp}")
            return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

        return jsonify(resp), status

    except Exception as e:
        logger.error(f"Error listing functions: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": f"Error listing functions - {e}"
        }), 500

@app.route('/health', methods=['GET'], strict_slashes=False)
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'})

def parse_sqs_request():
    """Parse SQS request parameters from query string or POST data"""
    data = {}

    if request.method == 'POST':
        # Try request.form first (parsed by Flask)
        if request.form:
            data = dict(request.form)
            logger.debug(f"Parsed from request.form: {list(data.keys())}")
            return data

        # Try request.args (query string)
        if request.args:
            data = dict(request.args)
            logger.debug(f"Parsed from request.args: {list(data.keys())}")
            return data

        # Parse raw body data (AWS CLI sends form-encoded in raw body)
        try:
            raw_data = request.get_data(as_text=True)
            if raw_data:
                logger.debug(f"Raw data: {raw_data[:200]}")
                parsed = parse_qs(raw_data, keep_blank_values=True)
                # parse_qs returns lists, get first value
                data = {k: v[0] if isinstance(v, list) and len(v) > 0 else v
                       for k, v in parsed.items()}
                logger.debug(f"Parsed from raw data: {list(data.keys())}")
                return data
        except Exception as e:
            logger.error(f"Error parsing raw data: {e}")
    else:
        # GET request - use query string
        data = dict(request.args)

    return data

# CloudWatch Logs API endpoint
# ============================================================================
@app.route('/logs', methods=['POST'])
def cloudwatch_logs_api():
    """
    CloudWatch Logs API endpoint
    Uses X-Amz-Target header to determine operation
    """
    # Proxy all CloudWatch Logs API calls to the authoritative lifecycle (lambda) service.
    # This keeps the lambda service as the primary sink for logs until a dedicated logs service exists.
    target = request.headers.get('X-Amz-Target', '')

    # Forward original headers and body
    proxied_headers = {}
    # Copy essential headers
    for h, v in request.headers.items():
        # Filter out Host header to let requests set it properly
        if h.lower() == 'host':
            continue
        proxied_headers[h] = v

    raw_body = request.get_data()

    status, data, resp = log_request('POST', '/logs', headers=proxied_headers, data=raw_body)

    # If log_request failed to reach lifecycle, return its error
    if resp is None:
        return jsonify(data), status

    # Build a Flask response from the lifecycle response
    try:
        content = resp.content
        # Preserve content-type if provided
        content_type = resp.headers.get('Content-Type', 'application/json')
        return Response(content, status=resp.status_code, content_type=content_type)
    except Exception:
        # Fallback to JSON response
        try:
            return jsonify(data), status
        except Exception:
            return jsonify({'message': 'Error proxying logs request'}), 500

@app.route('/2015-03-31/functions/<function_name>/logging-config', methods=['PUT'])
def put_function_logging_config(function_name):
    """
    Configure CloudWatch Logs for a Lambda function
    AWS API: PutFunctionLoggingConfig - proxy to lambda endpoint
    """
    try:
        logger.info(f"Setting logging config for: {function_name}")

        data = request.get_json() or {}

        # Proxy to lambda service endpoint
        status, resp, raw = log_request('PUT', f'/2015-03-31/functions/{function_name}/logging-config', json=data)

        if status >= 400:
            logger.warning(f"Lambda service returned error: {status} - {resp}")
            return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

        return jsonify(resp), status

    except Exception as e:
        logger.error(f"Error updating logging config: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": str(e)
        }), 500

@app.route('/2015-03-31/functions/<function_name>/logging-config', methods=['GET'])
def get_function_logging_config(function_name):
    """
    Get CloudWatch Logs configuration for a Lambda function
    AWS API: GetFunctionLoggingConfig - proxy to lambda endpoint
    """
    try:
        logger.info(f"Getting logging config for: {function_name}")

        # Proxy to lambda service endpoint
        status, resp, raw = log_request('GET', f'/2015-03-31/functions/{function_name}/logging-config')

        if status >= 400:
            logger.warning(f"Lambda service returned error: {status} - {resp}")
            return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

        return jsonify(resp), status

    except Exception as e:
        logger.error(f"Error getting logging config: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": str(e)
        }), 500

@app.route('/2015-03-31/functions/<function_name>/logging-config', methods=['DELETE'])
def delete_function_logging_config(function_name):
    """
    Delete custom CloudWatch Logs configuration for a Lambda function
    AWS API: DeleteFunctionLoggingConfig - proxy to lambda endpoint
    """
    try:
        logger.info(f"Deleting logging config for: {function_name}")

        # Proxy to lambda service endpoint
        status, resp, raw = log_request('DELETE', f'/2015-03-31/functions/{function_name}/logging-config')

        if status >= 400:
            logger.warning(f"Lambda service returned error: {status} - {resp}")
            return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

        return '', 204

    except Exception as e:
        logger.error(f"Error deleting logging config: {e}", exc_info=True)
        return jsonify({
            "__type": "ServiceException:",
            "message": str(e)
        }), 500


# Console
@app.route('/styles.css', methods=['GET'], strict_slashes=False)
def console_css():
    with open('console/styles.css', 'r') as f:
        html_content = f.read()
    return html_content, 200, {'Content-Type': 'text/css'}

@app.route('/logo.png', methods=['GET'], strict_slashes=False)
def console_nimbus():
    return send_file('console/nimbus-icon-transparent.png', mimetype='image/png')

@app.route('/app.js', methods=['GET'], strict_slashes=False)
def console_js():
    with open('console/app.js', 'r') as f:
        html_content = f.read()
    return html_content, 200, {'Content-Type': 'application/javascript'}

@app.route('/', methods=['POST', 'GET', 'PUT', 'DELETE', 'PATCH'], strict_slashes=False)
def handle_request():
    """Main handler for all API requests - routes to appropriate service"""

    # Get the action/operation from the request
    action = get_action_from_request()
    operation = get_aws_operation()
    if not operation:
        action, operation = get_service_from_user_agent()
    data = get_request_data()
    content_type = request.headers.get('Content-Type', '').lower()

    logger.debug(f"Request: method={request.method}, action={action}, operation={operation}, content_type={content_type}")

    # If this is an SQS API call (via X-Amz-Target or Action), proxy it to the SQS container
    SQS_ACTIONS = {
        'CreateQueue', 'DeleteQueue', 'GetQueueUrl', 'ListQueues',
        'SendMessage', 'SendMessageBatch', 'ReceiveMessage',
        'DeleteMessage', 'DeleteMessageBatch', 'ChangeMessageVisibility',
        'GetQueueAttributes', 'SetQueueAttributes', 'PurgeQueue'
    }

    if action in SQS_ACTIONS:
        logger.info(f"Routing to SQS handler: Operation={action}")
        AWS_ENDPOINT_URL_SQS = os.getenv('AWS_ENDPOINT_URL_SQS', 'http://sqs:4566')

        path = request.path
        qs = request.query_string.decode() if request.query_string else ''
        url = f"{AWS_ENDPOINT_URL_SQS}{path}"
        if qs:
            url = f"{url}?{qs}"

        skip = {"host", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade"}
        forward_headers = {k: v for k, v in request.headers.items() if k.lower() not in skip}
        forward_headers['X-Forwarded-For'] = request.remote_addr

        body = None
        if request.method in ('POST', 'PUT', 'PATCH'):
            body = request.get_data()

        try:
            resp = requests.request(request.method, url, headers=forward_headers, data=body, timeout=300)
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Failed to connect to SQS container at {AWS_ENDPOINT_URL_SQS}: {e}")
            return jsonify({'__type': 'ServiceException', 'message': 'SQS container unavailable'}), 503
        except Exception as e:
            logger.error(f"Error proxying SQS API request to container: {e}", exc_info=True)
            return jsonify({'__type': 'ServiceException', 'message': str(e)}), 500

        response_headers = {}
        excluded = {'content-encoding', 'content-length', 'transfer-encoding', 'connection'}
        for k, v in resp.headers.items():
            if k.lower() in excluded:
                continue
            response_headers[k] = v

        return Response(resp.content, status=resp.status_code, headers=response_headers)

    # DynamoDB operations
    DYNAMODB_ACTIONS = {
        'CreateTable', 'DescribeTable', 'ListTables', 'DeleteTable', 'UpdateTable',
        'PutItem', 'GetItem', 'UpdateItem', 'DeleteItem',
        'BatchWriteItem', 'BatchGetItem', 'Query', 'Scan',
        'CreateGlobalSecondaryIndex', 'UpdateGlobalSecondaryIndex',
        'DescribeTimeToLive', 'UpdateTimeToLive',
        'TagResource', 'UntagResource', 'ListTagsOfResource',
        'CreateBackup', 'DescribeBackup', 'ListBackups', 'DeleteBackup',
        'DescribeContinuousBackups', 'UpdateContinuousBackups',
        'DescribeStream', 'GetShardIterator', 'GetRecords',
        'TransactWriteItems', 'TransactGetItems'
    }

    if operation in DYNAMODB_ACTIONS:
        logger.info(f"Routing to DynamoDB handler: Operation={operation}")
        return proxy_to_dynamodb(operation, data)

    # SSM Parameter
    try:
        if operation == 'PutParameter':
            result = ssm.put_parameter(
                name=str(data['Name']),
                value=str(data['Value']),
                parameter_type=str(data.get('Type', 'String')),
                description=str(data.get('Description', '')),
                kms_key_id=str(data.get('KeyId')),
                overwrite=bool(data.get('Overwrite', False)),
                allowed_pattern=data.get('AllowedPattern', None),
                tags=data.get('Tags'),
                tier=str(data.get('Tier', 'Standard'))
            )
            return jsonify(result)

        elif operation == 'GetParameter':
            result = ssm.get_parameter(
                name=str(data['Name']),
                with_decryption=bool(data.get('WithDecryption', False))
            )
            return jsonify(result)

        elif operation == 'GetParameters':
            result = ssm.get_parameters(
                names=data['Names'],
                with_decryption=bool(data.get('WithDecryption', False))
            )
            return jsonify(result)

        elif operation == 'GetParametersByPath':
            result = ssm.get_parameters_by_path(
                path=str(data['Path']),
                recursive=bool(data.get('Recursive', False)),
                with_decryption=bool(data.get('WithDecryption', False)),
                max_results=int(data.get('MaxResults', 10))
            )
            return jsonify(result)

        elif operation == 'DeleteParameter':
            result = ssm.delete_parameter(name=str(data['Name']))
            return jsonify(result)

        elif operation == 'DescribeParameters':
            result = ssm.describe_parameters(
                filters=data.get('Filters'),
                max_results=int(data.get('MaxResults', 50))
            )
            return jsonify(result)

        elif operation == 'ListTagsForResource':
            result = ssm.get_parameter_tags(
                parameter_name=data['ResourceId']
            )
            return jsonify(result)

        elif operation == 'GetParameterHistory':
            result = ssm.get_parameter_history(
                name=str(data['Name']),
                with_decryption=bool(data.get('WithDecryption', False)),
                max_results=data.get('MaxResults', 50)
            )
            return jsonify(result)
    except ValueError as e:
        return jsonify({
            '__type': 'ParameterNotFound' if 'not found' in str(e) else 'InvalidParameterException',
            'message': str(e)
        }), 400
    except Exception as e:
        logger.error(f"SSM error: {e}", exc_info=True)
        return jsonify({
            '__type': 'InternalServerError',
            'message': str(e)
        }), 500

    ecr_handlers = {
        'CreateRepository': create_repository,
        'DeleteRepository': delete_repository,
        'DescribeRepositories': describe_repositories,
        'ListImages': list_images,
        'BatchGetImage': batch_get_image,
        'PutImage': put_image,
        'BatchDeleteImage': batch_delete_image,
        'GetAuthorizationToken': get_authorization_token,
        'DescribeImages': describe_images,
        'InitiateLayerUpload': initiate_layer_upload,
        'UploadLayerPart': upload_layer_part,
        'CompleteLayerUpload': complete_layer_upload,
    }
    if operation in ecr_handlers:
        # This is an ECR operation
        logger.info(f"Routing to ECR handler: Operation={operation}")


        handler = ecr_handlers.get(operation)
        if handler:
            return handler()

        return jsonify({
            "__type": "InvalidRequestException",
            "message": f"Operation {operation} not supported"
        }), 400

    s3_handlers = {
        'Ls': proxy_to_s3,
        'Cp': proxy_to_s3,
        'ListBuckets': proxy_to_s3,
        # 'CreateBucket': create_bucket,
        # 'DeleteBucket': delete_bucket,
        # 'PutObject': put_object,
        # 'GetObject': get_object,
        # 'DeleteObject': delete_object,
        # 'ListObjectsV2': list_objects_v2,
    }
    if operation in s3_handlers:
        logger.info(f"Routing to S3 handler: Operation={operation}")
        return proxy_to_s3()

    # if operation in s3_handlers:
    #     # This is an S3 operation
    #     logger.info(f"Routing to S3 handler: Operation={operation}")

    #     handler = s3_handlers.get(operation)
    #     if handler:
    #         return handler()

    #     return jsonify({
    #         "__type": "InvalidRequestException",
    #         "message": f"Operation {operation} not supported"
    #     }), 400

    logs_handlers = {
        'CreateLogGroup': proxy_logs_to_lambda,
        'CreateLogStream': proxy_logs_to_lambda,
        'PutLogEvents': proxy_logs_to_lambda,
        'GetLogEvents': proxy_logs_to_lambda,
        'DescribeLogGroups': proxy_logs_to_lambda,
        'DescribeLogStreams': proxy_logs_to_lambda,
        'FilterLogEvents': proxy_logs_to_lambda,
        'DeleteLogGroup': proxy_logs_to_lambda,
        'DeleteLogStream': proxy_logs_to_lambda,
    }
    if operation in logs_handlers:
        # This is an S3 operation
        logger.info(f"Routing to Log handler: Operation={operation}")

        handler = logs_handlers.get(operation)
        if handler:
            return handler(data=data, operation=operation)

        return jsonify({
            "__type": "InvalidRequestException",
            "message": f"Operation {operation} not supported"
        }), 400

    # ========================================================================
    # Unknown request type - We now have a simple simple simple console
    # ========================================================================
    if request.headers.get('Content-Type', '').lower() == 'application/x-amz-json-1.0':
        logger.warning(f"Unknown request type")
        logger.warning(f"  URL: {request.url}")
        logger.warning(f"  Action: {action}")
        logger.warning(f"  Operation: {operation}")
        logger.warning(f"  Content-Type: {content_type}")
        logger.warning(f"  X-Amz-Target: {request.headers.get('X-Amz-Target')}")
        logger.warning(f"  All Headers: {request.headers}")

        return jsonify({
            'Error': {
                'Type': 'Sender',
                'Code': 'UnsupportedOperation',
                'Message': 'The requested operation is not supported'
            }
        }), 400

    # Console index.html
    with open('console/index.html', 'r') as f:
        html_content = f.read()
    return html_content, 200, {'Content-Type': 'text/html'}

# SQS handler
@app.route('/<account_id>/<queue_name>', methods=['POST', 'GET', 'DELETE'])
def sqs_queue_operations(account_id, queue_name):
    """Proxy SQS HTTP API to the Lambda container service at LAMBDA_CONTAINER_ENDPOINT.
    Forward the incoming request (path, query string, headers, body) to the Lambda container
    and return its response to the client. This keeps behavior consistent with runtime_next_invocation().
    """
    AWS_ENDPOINT_URL_SQS = os.getenv('AWS_ENDPOINT_URL_SQS', 'http://sqs:4566')

    # Build proxied URL including query string
    path = request.path
    qs = request.query_string.decode() if request.query_string else ''
    url = f"{AWS_ENDPOINT_URL_SQS}{path}"
    if qs:
        url = f"{url}?{qs}"

    # Prepare headers to forward (exclude hop-by-hop headers)
    skip = {"host", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade"}
    forward_headers = {k: v for k, v in request.headers.items() if k.lower() not in skip}
    forward_headers['X-Forwarded-For'] = request.remote_addr

    # Prepare body if present
    body = None
    if request.method in ('POST', 'PUT', 'PATCH'):
        body = request.get_data()

    try:
        resp = requests.request(request.method, url, headers=forward_headers, data=body, timeout=300)
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Failed to connect to Lambda container at {AWS_ENDPOINT_URL_SQS}: {e}")
        return jsonify({'__type': 'ServiceException', 'message': 'Lambda container unavailable'}), 503
    except Exception as e:
        logger.error(f"Error proxying SQS request to Lambda container: {e}", exc_info=True)
        return jsonify({'__type': 'ServiceException', 'message': str(e)}), 500

    # Build Flask response from proxied response
    response_headers = {}
    excluded = {'content-encoding', 'content-length', 'transfer-encoding', 'connection'}
    for k, v in resp.headers.items():
        if k.lower() in excluded:
            continue
        response_headers[k] = v

    return Response(resp.content, status=resp.status_code, headers=response_headers)


def to_camel_case(s):
    # Convert "list-buckets" -> "ListBuckets"
    return ''.join(word.capitalize() for word in s.split('-'))

def get_service_from_user_agent():
    ua = request.headers.get('User-Agent', '')
    match = re.search(r'md/command#([\w\-]+)\.([\w\-]+)', ua)
    if match:
        service = match.group(1)
        operation = match.group(2)
        return service.upper(), to_camel_case(operation)
    return None, None

def get_aws_operation():
    """Extract AWS operation from headers"""
    target = request.headers.get('X-Amz-Target', '')
    if target:
        return target.split('.')[-1]
    return None

def get_action_from_request():
    """
    Extract Action from request, handling multiple protocols:
    1. X-Amz-Target header (JSON protocol): "AmazonSQS.CreateQueue"
    2. Query string: ?Action=CreateQueue
    3. Form-encoded body: Action=CreateQueue&...
    """
    action = None

    # Method 1: Check X-Amz-Target header (JSON protocol)
    # Format: "AmazonSQS.CreateQueue" or "CreateQueue"
    target = request.headers.get('X-Amz-Target', '')
    if target:
        if '.' in target:
            action = target.split('.')[-1]  # "AmazonSQS.CreateQueue" → "CreateQueue"
        else:
            action = target
        logger.debug(f"Action from X-Amz-Target: {action}")
        return action

    # Method 2: Check query string
    action = request.args.get('Action')
    if action:
        logger.debug(f"Action from query string: {action}")
        return action

    # Method 3: Check form data (if Flask parsed it)
    action = request.form.get('Action')
    if action:
        logger.debug(f"Action from form data: {action}")
        return action

    # Method 4: Parse raw body if form-encoded
    content_type = request.headers.get('Content-Type', '').lower()

    if 'application/x-www-form-urlencoded' in content_type:
        try:
            raw_data = request.get_data(as_text=True)
            if raw_data:
                parsed = parse_qs(raw_data, keep_blank_values=True)
                action = parsed.get('Action', [None])[0]
                if action:
                    logger.debug(f"Action from raw form data: {action}")
                    return action
        except Exception as e:
            logger.error(f"Error parsing form data: {e}")

    return None

# S3 API
# ============================================================================
def check_s3_service_from_user_agent():
    ua = request.headers.get('User-Agent', '')
    match = re.search(r'md/command#([\w\-]+)\.([\w\-]+)', ua)
    if match:
        service = match.group(1)  # 's3api' or 's3'
        operation = match.group(2)  # 'create-bucket', 'ls'
        return service, operation
    return None, None

def proxy_to_s3():
    """Proxy S3 requests to S3 backend - preserve signature by keeping original host"""
    S3_ENDPOINT = os.getenv('S3_ENDPOINT', 'http://s3:9000')

    s3_url = f"{S3_ENDPOINT}{request.path}"
    if request.query_string:
        s3_url += f"?{request.query_string.decode()}"

    # Keep ALL headers INCLUDING the original Host (critical for signature validation)
    headers = {k: v for k, v in request.headers}
    request_data =request.get_data()

    logger.debug(f"Proxying to S3: {request.method} {s3_url}")
    logger.debug(f"Host header: {headers.get('Host')}")
    logger.debug(f"Data: {request_data}")
    resp = requests.request(
        method=request.method,
        url=s3_url,
        headers=headers,
        data=request_data,
        stream=True
    )

    logger.debug(f"S3 response: {resp.status_code}")
    logger.debug(f"S3 Content-Type: {resp.headers.get('Content-Type')}")

    # Build response with proper headers
    excluded = {'transfer-encoding', 'connection'}
    response_headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
    logger.critical(f'{response_headers}')
    return Response(resp.content, status=resp.status_code, headers=response_headers)

# Handles aws cli s3 commands
@app.route('/<bucket_name>', methods=['PUT'])
def handle_bucket_operations(bucket_name):
    """Handle bucket-level operations like notification configuration"""

    # Check if this is a notification configuration request
    if 'notification' in request.args:
        # Extract from request body (JSON or form-encoded)
        data = get_request_data()

        # The actual MinIO config is already set globally via webhook in Dockerfile
        notification_id = data.get('Id', f"notification-{int(time.time() * 1000)}") # TODO use this if notification not set
        queue_arn = data.get('QueueArn') or data.get('Queue')
        events = data.get('Events', [])

        logger.critical(f'--DATA-- {data}')

        # Handle both direct events list or nested in QueueConfiguration
        if 'QueueConfigurations' in data:
            set_bucket_webhook_notication(bucket_name, queue_arn.split(':')[-1])

            # Batch config
            for config in data['QueueConfigurations']:
                save_single_notification_config(bucket_name, config)
        else:
            # Single config
            save_single_notification_config(bucket_name, data)

        # Return success (don't proxy to MinIO)
        return Response('', status=200)

    # Otherwise, proxy to S3 normally
    return proxy_to_s3()

def set_bucket_webhook_notication(bucket_name, queue_name):
    config_payload = {
        "key_values": {
            "notify_webhook:1": f"endpoint=http://api:4566/webhook/sqs/{queue_name} queue_limit=1000 enable=on"
        }
    }

    # Prepare SigV4 auth
    creds = Credentials('localcloud', 'localcloud')
    request = AWSRequest(
        method="PUT",
        url=f"http://s3:9000/minio/admin/v3/set-config-kv",
        data=json.dumps(config_payload),
        headers={"Content-Type": "application/json"}
    )
    SigV4Auth(creds, "s3", "us-east-1").add_auth(request)

    # Convert AWSRequest to requests-compatible
    auth_headers = dict(request.headers.items())

    # Send the request
    data = json.dumps(config_payload)

    resp = requests.put(f"http://s3:9000/minio/admin/v3/set-config-kv", headers=auth_headers, data=data)

    logger.critical(f'STATUS: {resp.status_code}')
    logger.critical(f'RESPONSE: {resp.text}')

def save_single_notification_config(bucket_name, config):
    """Helper to save a single notification configuration"""
    notification_id = config.get('Id', f"notification-{int(time.time() * 1000)}")
    queue_arn = config.get('QueueArn') or config.get('Queue')
    events = config.get('Events', [])

    # Extract filter rules
    filter_rules = []
    filter_config = config.get('Filter', {})
    if filter_config:
        key_filters = filter_config.get('Key', {})
        filter_rules = key_filters.get('FilterRules', [])

    # Convert queue ARN to queue URL
    queue_name = queue_arn.split(':')[-1]
    queue_url = f"http://sqs:4566/{ACCOUNT_ID}/{queue_name}"

    # Save to database
    db.save_notification_config(
        bucket_name=bucket_name,
        notification_id=notification_id,
        queue_arn=queue_arn,
        queue_url=queue_url,
        event_patterns=events,
        filter_rules=filter_rules
    )

    logger.info(f"Saved notification config {notification_id} for bucket {bucket_name}")

# TODO try make api dynamically create bucket->queue webhooks for each bucket event
def configure_bucket_notification_webhook(bucket_name, notification_id, queue_arn, events=[], filters=[]):
    # Extract queue name from ARN
    queue_name = queue_arn.split(':')[-1]

    # Create unique webhook ID
    webhook_id = f"webhook-{notification_id}"

    s3 = boto3.client(
        "s3",
        endpoint_url="http://s3:9000",
        aws_access_key_id="localcloud",
        aws_secret_access_key="localcloud",
        config=Config(signature_version="s3v4"),
        region_name="us-east-1"
    )

    notification_config = {
        "QueueConfigurations": [
            {
                "Id": "webhook-config",
                "QueueArn": "arn:minio:sqs::1:webhook",
                "Events": ["s3:ObjectCreated:*"],  # Change to whatever events you want
            }
        ]
    }

    s3.put_bucket_notification_configuration(
        Bucket=bucket_name,
        NotificationConfiguration=notification_config
    )

@app.route('/<bucket_name>', methods=['GET'])
def handle_bucket_get_operations(bucket_name):
    """Handle GET operations on buckets"""

    # Check if this is a notification configuration request
    if 'notification' in request.args:
        # Return configs from database in S3 API format
        configs = db.get_bucket_notification_configs(bucket_name)

        queue_configurations = []
        for config in configs:
            events = json.loads(config['event_patterns']) if isinstance(config['event_patterns'], str) else config['event_patterns']
            filter_rules = json.loads(config['filter_rules']) if config.get('filter_rules') and isinstance(config['filter_rules'], str) else []

            queue_config = {
                'Id': config['notification_id'],
                'QueueArn': config['queue_arn'],
                'Events': events
            }

            if filter_rules:
                queue_config['Filter'] = {
                    'Key': {
                        'FilterRules': filter_rules
                    }
                }

            queue_configurations.append(queue_config)

        # Return JSON response
        # return jsonify({
        #     'QueueConfigurations': queue_configurations
        # }), 200
        # Build XML string - some reason this one requies xml???
        xml_body = "<NotificationConfiguration>\n"
        for q in queue_configurations:
            xml_body += f"""
            <QueueConfiguration>
                <Id>{q['Id']}</Id>
                <Queue>{q['QueueArn']}</Queue>
                <Event>{q['Event']}</Event>
            </QueueConfiguration>
            """
        xml_body += "\n</NotificationConfiguration>"
        # Future - TopicConfigurations
        # TODO - LambdaFunctionConfigurations
        return Response(xml_body, status=200, mimetype='application/xml')

    # Otherwise, proxy to S3 normally
    return proxy_to_s3()

# TODO
# def handle_get_bucket_notification(bucket_name):
#     """Intercept and transform GET notification configuration responses"""
#     try:
#         # Use boto3 to get from MinIO (clean!)
#         s3_client = get_s3_client()
#         response = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)

#         # Transform MinIO webhook ARNs back to user queue ARNs
#         if 'QueueConfigurations' in response:
#             for config in response['QueueConfigurations']:
#                 minio_arn = config.get('QueueArn')
#                 notification_id = config.get('Id')

#                 # Actually, not sure we need this at all now
#                 # if minio_arn and minio_arn.startswith('arn:minio:'):
#                     # Look up the original user queue ARN
#                     # mapping = db.get_s3_notification_mapping(bucket_name, minio_arn)
#                     # if mapping and mapping['notification_id'] == notification_id:
#                     #     config['QueueArn'] = mapping['user_queue_arn']
#                     #     logger.info(f"Restored ARN: {minio_arn} -> {mapping['user_queue_arn']}")


#     except Exception as e:
#         logger.error(f"Error getting notification configuration: {e}", exc_info=True)

#         # Return empty configuration XML (valid response when no notifications configured)
#         empty_config = '<?xml version="1.0" encoding="UTF-8"?>\n<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>'
#         return Response(empty_config, status=200, mimetype='application/xml')

@app.route('/s3/buckets/<bucket_name>/notification', methods=['GET'])
def get_bucket_notifications(bucket_name):
    """Get bucket notification configuration from database"""
    try:
        configs = db.get_bucket_notification_configs(bucket_name)

        queue_configurations = []
        for config in configs:
            # Parse JSON strings
            events = json.loads(config['event_patterns']) if isinstance(config['event_patterns'], str) else config['event_patterns']
            filter_rules = json.loads(config['filter_rules']) if config.get('filter_rules') and isinstance(config['filter_rules'], str) else []

            queue_config = {
                'Id': config['notification_id'],
                'QueueArn': config['queue_arn'],
                'Events': events
            }

            if filter_rules:
                queue_config['Filter'] = {
                    'Key': {
                        'FilterRules': filter_rules
                    }
                }

            queue_configurations.append(queue_config)

        return jsonify({
            'QueueConfigurations': queue_configurations
        }), 200

    except Exception as e:
        logger.error(f"Error retrieving bucket notifications: {e}", exc_info=True)
        return jsonify({
            '__type': 'ServiceException',
            'message': str(e)
        }), 500

def put_bucket_notification_configuration(bucket_name, configuration):
    # bucket_name, queue_arn
    session = get_boto3_session()
    s3_client = session.client('s3', endpoint_url=S3_ENDPOINT)
    logger.critical(f'Put Configuration: {configuration}')
    # TODO mapping SQS to minio webhook
    # if 'QueueArn' in configuration:
    #     queue_arn = configuration['QueueArn']
    #     self._writing_sqs_mapping(queue_arn, webhook_arn)

    configure_bucket_notification_webhook(bucket_name, time.time(), configuration['QueueArn'].split(':')[-1])

    configuration['QueueArn'] = 'arn:minio:sqs::1:webhook'
    try:
        return jsonify({
            '__type': 'ServiceException',
            'message': s3_client.put_bucket_notification_configuration(
                Bucket=bucket_name,
                NotificationConfiguration={
                    'QueueConfigurations': [
                        configuration
                    ]
                }
            )}
        ), 200
    except Exception as e:
        return jsonify({
            '__type': 'ServiceException',
            'message': str(e)
        }), 500

# TODO Handles web console s3 commands
@app.route('/s3/buckets/<bucket_name>/notification', methods=['POST'])
def put_bucket_notifications(bucket_name):
    """Set bucket notification configuration - saves to DB only"""
    try:
        data = request.get_json() or {}

        if 'configuration' not in data:
            return jsonify({
                '__type': 'InvalidParameterException',
                'message': "Missing 'configuration' in request"
            }), 400

        config = data['configuration']
        queue_arn = config.get('QueueArn')
        notification_id = config.get('Id')
        events = config.get('Events', [])
        filter_config = config.get('Filter', {})

        if not queue_arn or not notification_id:
            return jsonify({
                '__type': 'InvalidParameterException',
                'message': "QueueArn and Id are required in configuration"
            }), 400

        # Extract filter rules
        filter_rules = []
        if filter_config:
            key_filters = filter_config.get('Key', {})
            filter_rules = key_filters.get('FilterRules', [])

        # Convert queue ARN to queue URL
        # ARN format: arn:aws:sqs:region:account:queue-name
        queue_name = queue_arn.split(':')[-1]
        queue_url = f"http://sqs:4566/{ACCOUNT_ID}/{queue_name}"  # TODO um, do we need the url or just arn?

        # push minio webhook changes
        # set_bucket_webhook_notication(bucket_name, queue_name)
        put_bucket_notification_configuration(bucket_name, config)

        # Save to database
        db.save_notification_config(
            bucket_name=bucket_name,
            notification_id=notification_id,
            queue_arn=queue_arn,
            queue_url=queue_url,
            event_patterns=events,
            filter_rules=filter_rules
        )

        logger.info(f"Saved notification config {notification_id} for bucket {bucket_name}")

        return jsonify({
            'success': True,
            'configuration': config
        }), 200

    except Exception as e:
        logger.error(f"Error setting bucket notifications: {e}", exc_info=True)
        return jsonify({
            '__type': 'ServiceException',
            'message': str(e)
        }), 500

@app.route('/s3/buckets/<bucket_name>/notification/<notification_id>', methods=['DELETE'])
def delete_bucket_notification(bucket_name, notification_id):
    """Delete a specific bucket notification configuration"""
    try:
        db.delete_notification_config(bucket_name, notification_id)

        logger.info(f"Deleted notification {notification_id} from bucket {bucket_name}")
        return jsonify({'success': True}), 200

    except Exception as e:
        logger.error(f"Error deleting bucket notification: {e}", exc_info=True)
        return jsonify({
            '__type': 'ServiceException',
            'message': str(e)
        }), 500

@app.route('/s3/buckets/<bucket_name>/lifecycle', methods=['GET'])
def get_bucket_lifecycle(bucket_name):
    """Get bucket lifecycle configuration from MinIO"""
    try:
        from botocore.exceptions import ClientError

        s3_client = get_s3_client()

        try:
            response = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            return jsonify({'Rules': response.get('Rules', [])}), 200

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ('NoSuchLifecycleConfiguration', 'NoSuchBucket'):
                return jsonify({'Rules': []}), 200
            raise

    except Exception as e:
        logger.error(f"Error getting lifecycle configuration: {e}", exc_info=True)
        return jsonify({'__type': 'ServiceException', 'message': str(e)}), 500

@app.route('/s3/buckets/<bucket_name>/lifecycle', methods=['POST'])
def add_bucket_lifecycle_rule(bucket_name):
    """Add a lifecycle rule to bucket"""
    try:
        from botocore.exceptions import ClientError

        data = request.get_json() or {}
        new_rule = data.get('rule')

        if not new_rule:
            return jsonify({'__type': 'InvalidParameterException', 'message': 'Missing rule'}), 400

        s3_client = get_s3_client()

        # Get existing rules
        existing_rules = []
        try:
            response = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            existing_rules = response.get('Rules', [])
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code not in ('NoSuchLifecycleConfiguration', 'NoSuchBucket'):
                raise

        # Check for duplicate ID
        rule_id = new_rule.get('ID')
        if any(r.get('ID') == rule_id for r in existing_rules):
            return jsonify({'__type': 'InvalidParameterException', 'message': f'Rule ID {rule_id} exists'}), 400

        # Add and save
        existing_rules.append(new_rule)
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration={'Rules': existing_rules}
        )

        logger.info(f"Added lifecycle rule {rule_id} to {bucket_name}")
        return jsonify({'success': True, 'rule': new_rule}), 200

    except Exception as e:
        logger.error(f"Error adding lifecycle rule: {e}", exc_info=True)
        return jsonify({'__type': 'ServiceException', 'message': str(e)}), 500

@app.route('/s3/buckets/<bucket_name>/lifecycle/<rule_id>', methods=['DELETE'])
def delete_bucket_lifecycle_rule(bucket_name, rule_id):
    """Delete a specific lifecycle rule"""
    try:
        from botocore.exceptions import ClientError

        s3_client = get_s3_client()

        try:
            response = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            rules = response.get('Rules', [])
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'NoSuchLifecycleConfiguration':
                return jsonify({
                    '__type': 'NoSuchLifecycleConfiguration',
                    'message': 'No lifecycle config'
                }), 404
            raise

        # Remove the rule
        updated_rules = [r for r in rules if r.get('ID') != rule_id]

        if len(updated_rules) == len(rules):
            return jsonify({
                '__type': 'NoSuchLifecycleRule',
                'message': f'Rule {rule_id} not found'
            }), 404

        # Update or delete config
        if updated_rules:
            s3_client.put_bucket_lifecycle_configuration(
                Bucket=bucket_name,
                LifecycleConfiguration={'Rules': updated_rules}
            )
        else:
            s3_client.delete_bucket_lifecycle(Bucket=bucket_name)

        logger.info(f"Deleted lifecycle rule {rule_id} from {bucket_name}")
        return jsonify({'success': True}), 200

    except Exception as e:
        logger.error(f"Error deleting lifecycle rule: {e}", exc_info=True)
        return jsonify({
            '__type': 'ServiceException',
            'message': str(e)
        }), 500

@app.route('/s3/buckets', methods=['GET'])
def list_s3_buckets():
    """Proxy S3 ListBuckets for web console"""
    try:
        # Use boto3 to list buckets (handles auth automatically)
        session = get_boto3_session()
        s3_client = session.client('s3', endpoint_url=S3_ENDPOINT)

        response = s3_client.list_buckets()

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Error listing S3 buckets: {e}", exc_info=True)
        return jsonify({
            '__type': 'ServiceException',
            'message': str(e)
        }), 500

@app.route('/s3/buckets', methods=['POST'])
def create_s3_bucket():
    """Create S3 bucket for web console"""
    try:
        data = request.get_json() or {}
        bucket_name = data.get('bucketName')

        if not bucket_name:
            return jsonify({'__type': 'InvalidParameterException', 'message': 'bucketName required'}), 400

        s3_client = get_s3_client()
        s3_client.create_bucket(Bucket=bucket_name)

        return jsonify({'success': True}), 200

    except Exception as e:
        logger.error(f"Error creating S3 bucket: {e}", exc_info=True)
        return jsonify({'__type': 'ServiceException', 'message': str(e)}), 500

@app.route('/s3/buckets/<bucket_name>', methods=['DELETE'])
def delete_s3_bucket(bucket_name):
    """Delete S3 bucket for web console"""
    try:
        force = request.args.get('force', 'false').lower() == 'true'

        s3_client = get_s3_client()

        if force:
            # Delete all objects first
            paginator = s3_client.get_paginator('list_objects_v2')
            for page in paginator.paginate(Bucket=bucket_name):
                if 'Contents' in page:
                    objects = [{'Key': obj['Key']} for obj in page['Contents']]
                    s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': objects})

        s3_client.delete_bucket(Bucket=bucket_name)

        return jsonify({'success': True}), 200

    except s3_client.exceptions.NoSuchBucket:
        return jsonify({'__type': 'NoSuchBucket', 'message': 'Bucket does not exist'}), 404
    except Exception as e:
        error_message = str(e)
        if 'BucketNotEmpty' in error_message:
            return jsonify({
                '__type': 'BucketNotEmpty',
                'message': 'The bucket is not empty. Delete all objects first or use force delete.'
            }), 409
        logger.error(f"Error deleting S3 bucket: {e}", exc_info=True)
        return jsonify({'__type': 'ServiceException', 'message': str(e)}), 500

@app.route('/s3/buckets/<bucket_name>/objects/<path:key>/metadata', methods=['GET'])
def get_s3_object_metadata(bucket_name, key):
    """Get object metadata for web console"""
    try:
        s3_client = get_s3_client()

        # Get object metadata
        response = s3_client.head_object(Bucket=bucket_name, Key=key)

        # Build object URL
        S3_ENDPOINT = os.getenv('S3_ENDPOINT_URL', 'http://s3:9000')
        object_url = f"{S3_ENDPOINT}/{bucket_name}/{key}"

        metadata = {
            'Key': key,
            'Bucket': bucket_name,
            'Size': response.get('ContentLength', 0),
            'LastModified': response.get('LastModified').isoformat() if response.get('LastModified') else None,
            'ETag': response.get('ETag', '').strip('"'),
            'ContentType': response.get('ContentType', 'application/octet-stream'),
            'StorageClass': response.get('StorageClass', 'STANDARD'),
            'ServerSideEncryption': response.get('ServerSideEncryption'),
            'VersionId': response.get('VersionId'),
            'Metadata': response.get('Metadata', {}),
            'ObjectUrl': object_url,
            'ARN': f'arn:aws:s3:::{bucket_name}/{key}'
        }

        return jsonify(metadata), 200

    except Exception as e:
        logger.error(f"Error getting S3 object metadata: {e}", exc_info=True)
        return jsonify({'__type': 'ServiceException', 'message': str(e)}), 500

@app.route('/s3/buckets/<bucket_name>/objects', methods=['GET'])
def list_s3_objects(bucket_name):
    """List objects in S3 bucket for web console"""
    try:
        prefix = request.args.get('prefix', '')

        s3_client = get_s3_client()

        params = {'Bucket': bucket_name}
        if prefix:
            params['Prefix'] = prefix
        params['Delimiter'] = '/'

        response = s3_client.list_objects_v2(**params)

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Error listing S3 objects: {e}", exc_info=True)
        return jsonify({'__type': 'ServiceException', 'message': str(e)}), 500

@app.route('/s3/buckets/<bucket_name>/objects/<path:key>', methods=['DELETE'])
def delete_s3_object(bucket_name, key):
    """Delete object from S3 bucket for web console"""
    try:
        s3_client = get_s3_client()
        s3_client.delete_object(Bucket=bucket_name, Key=key)

        return jsonify({'success': True}), 200

    except Exception as e:
        logger.error(f"Error deleting S3 object: {e}", exc_info=True)
        return jsonify({'__type': 'ServiceException', 'message': str(e)}), 500

@app.route('/s3/buckets/<bucket_name>/objects/<path:key>', methods=['GET'])
def get_s3_object(bucket_name, key):
    """Download object from S3 bucket for web console"""
    try:
        s3_client = get_s3_client()
        response = s3_client.get_object(Bucket=bucket_name, Key=key)

        # Stream the file back to client
        return Response(
            response['Body'].read(),
            mimetype=response.get('ContentType', 'application/octet-stream'),
            headers={
                'Content-Disposition': f'attachment; filename="{key.split("/")[-1]}"'
            }
        )

    except Exception as e:
        logger.error(f"Error getting S3 object: {e}", exc_info=True)
        return jsonify({'__type': 'ServiceException', 'message': str(e)}), 500

@app.route('/s3/buckets/<bucket_name>/objects', methods=['POST'])
def upload_s3_object(bucket_name):
    """Upload object to S3 bucket for web console"""
    try:
        # Get from form or use path parameter
        key = request.form.get('key')
        file = request.files.get('file')

        if not all([key, file]):
            return jsonify({'__type': 'InvalidParameterException', 'message': 'key and file required'}), 400

        s3_client = get_s3_client()
        s3_client.upload_fileobj(file, bucket_name, key)

        return jsonify({'success': True}), 200

    except Exception as e:
        logger.error(f"Error uploading S3 object: {e}", exc_info=True)
        return jsonify({'__type': 'ServiceException', 'message': str(e)}), 500

@app.route('/s3/buckets/<bucket_name>/objects/copy', methods=['POST'])
def copy_s3_object():
    """Copy/rename/move S3 object for web console"""
    try:
        data = request.get_json() or {}
        source_key = data.get('sourceKey')
        dest_bucket = data.get('destBucket')
        dest_key = data.get('destKey')
        delete_source = data.get('deleteSource', False)

        if not all([source_key, dest_bucket, dest_key]):
            return jsonify({'__type': 'InvalidParameterException', 'message': 'sourceKey, destBucket, destKey required'}), 400

        s3_client = get_s3_client()

        # Copy object
        copy_source = {'Bucket': request.view_args['bucket_name'], 'Key': source_key}
        s3_client.copy_object(CopySource=copy_source, Bucket=dest_bucket, Key=dest_key)

        # Delete source if moving
        if delete_source:
            s3_client.delete_object(Bucket=request.view_args['bucket_name'], Key=source_key)

        return jsonify({'success': True}), 200

    except Exception as e:
        logger.error(f"Error copying S3 object: {e}", exc_info=True)
        return jsonify({'__type': 'ServiceException', 'message': str(e)}), 500

# Also add a catch-all to see what URLs are being hit
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def catch_all(path):
    # Then in handle_request():
    service, operation = get_service_from_user_agent()
    if service and service.lower() in ('s3', 's3api'):
        # if operation == 'PutBucketNotificationConfiguration':
        #     return handle_put_bucket_notification(path)
        # elif operation == 'GetBucketNotificationConfiguration':
        #     return handle_get_bucket_notification(path)

        logger.info(f"Routing to S3: service={service}, operation={operation}")
        return proxy_to_s3()

    """Catch-all route for debugging"""
    logger.warning(f"Unhandled route: {request.method} /{path}")
    logger.warning(f"Operation detected: {operation}")
    logger.warning(f"Query params: {vars(request.args)}")
    logger.warning(f"Available routes: {[str(rule) for rule in app.url_map.iter_rules()]}")
    try:
        data = request.get_json() or {}
        logger.warning(f'Data: {json.dumps(data)}')
    except Exception as e:
        pass
    return jsonify({
        'errorMessage': f'Route not found: {request.method} /{path}',
        'errorType': 'RouteNotFoundException',
        'availableRoutes': [str(rule) for rule in app.url_map.iter_rules()]
    }), 404

def get_function_by_container_ip(container_ip):
    """Look up function name by container IP address"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT function_name FROM container_mappings
        WHERE container_ip = ?
    ''', (container_ip,))

    row = cursor.fetchone()
    conn.close()

    if row:
        logger.info(f"Found function {row[0]} for IP {container_ip}")
        return row[0]

    logger.warning(f"No function found for IP {container_ip}")
    return None

def get_function_by_container_id(container_id):
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

def delete_container_mapping(function_name):
    """Delete container mapping for a function"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('DELETE FROM container_mappings WHERE function_name = ?',
                   (function_name,))

    conn.commit()
    conn.close()
    logger.info(f"Deleted container mapping for {function_name}")

def list_container_mappings():
    """List all container mappings"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM container_mappings')
    rows = cursor.fetchall()
    conn.close()

    mappings = []
    for row in rows:
        mappings.append({
            'function_name': row[0],
            'container_id': row[1],
            'container_ip': row[2],
            'created_at': row[3]
        })

    return mappings

def get_container_for_function(function_name):
    """Get the Docker container for a function"""
    try:
        container_name = f"localcloud-{function_name}"
        return docker_client.containers.get(container_name)
    except docker.errors.NotFound:
        return None

# ESM
# ============================================================================
# Event Source Mapping Initialization
# ===========================================================================

# API Endpoints
@app.route('/2015-03-31/event-source-mappings/', methods=['POST'], strict_slashes=False)
def create_event_source_mapping_endpoint():
    """Create event source mapping"""
    data = request.get_json() or {}
    logger.info(f"Creating ESM (proxy) with data: {data}")
    status, resp = esm_request('POST', '/2015-03-31/event-source-mappings/', json=data)
    return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

@app.route('/2015-03-31/event-source-mappings/', methods=['GET'], strict_slashes=False)
def list_event_source_mapping_endpoint():
    """List event source mappings"""
    function_name = request.args.get('FunctionName', default='', type=str)
    status, resp = esm_request('GET', f'/2015-03-31/event-source-mappings/?FunctionName={function_name}' if function_name else '/2015-03-31/event-source-mappings/')
    return (jsonify(resp), status) if isinstance(resp, dict) else (resp, status)

@app.route('/2015-03-31/event-source-mappings/<uuid>', methods=['GET'], strict_slashes=False)
def get_event_source_mapping(uuid):
    """Get event source mapping details"""
    status, resp = esm_request('GET', f'/2015-03-31/event-source-mappings/{uuid}')
    if status == 200:
        return jsonify(resp), 200
    return jsonify({'__type': 'ResourceNotFoundException'}), 404

@app.route('/2015-03-31/event-source-mappings/<uuid>', methods=['PUT'], strict_slashes=False)
def update_event_source_mapping_endpoint(uuid):
    """Update event source mapping"""
    data = request.get_json() or {}
    status, resp = esm_request('PATCH', f'/2015-03-31/event-source-mappings/{uuid}', json=data)
    if status == 200:
        return jsonify(resp)
    return jsonify({'__type': 'ResourceNotFoundException'}), 404

@app.route('/2015-03-31/event-source-mappings/<uuid>', methods=['DELETE'], strict_slashes=False)
def delete_event_source_mapping_endpoint(uuid):
    """Delete event source mapping"""
    status, _ = esm_request('DELETE', f'/2015-03-31/event-source-mappings/{uuid}')
    if status in (200, 202, 204):
        return '', 204
    return jsonify({'__type': 'ResourceNotFoundException'}), 404

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    db.init_db()

    # SSM Parameters
    ssm = SSMParameterStore(
        account_id=ACCOUNT_ID,
        region=REGION,)

    try:
        # Start Flask app
        app.run(host='0.0.0.0', port=4566, debug=False)
    finally:
        # Graceful shutdown
        logger.info("Shutting down...")

        logger.info("Shutdown complete")
