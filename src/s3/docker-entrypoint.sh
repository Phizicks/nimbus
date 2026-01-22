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

while true; do
    curl -q http://api:4566/health > /dev/null 2>&1
    [ $? -eq 0 ] && break
    sleep 1
done

# Add webhook target and enable it TODO, move to service to bootstrap first setup
mc admin config set localcloud notify_webhook:1 endpoint=http://api:4566/webhook/sqs queue_limit=1000
mc admin config set localcloud notify_webhook:1 enable=on

# Restart MinIO service (non-interactive)
mc admin service restart --json localcloud

echo -e "localcloud\nlocalcloud" | mc alias set localcloud http://api:4566

# Keep container alive
wait
