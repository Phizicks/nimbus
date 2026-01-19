#!/bin/sh

# Start MinIO in the background
/usr/bin/minio server /data --console-address :9001 &

# Wait until MinIO API is ready
echo "Waiting for MinIO to start..."
while ! curl -s http://127.0.0.1:9000 > /dev/null; do
    sleep 1
    echo -n "."
done
echo "MinIO started."

# Configure mc alias
mc alias set localcloud http://127.0.0.1:9000 $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD

# Add webhook target and enable it
mc admin config set localcloud notify_webhook:1 endpoint=http://api:4566/webhook/s3 queue_limit=1000
mc admin config set localcloud notify_webhook:1 enable=on

# Restart MinIO service (non-interactive)
mc admin service restart --json localcloud

# Keep container alive
wait
