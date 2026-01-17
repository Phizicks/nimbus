# Nimbus LocalCloud - Free AWS Services Emulator

A **complete, free AWS services emulator** for local development. Nimbus provides the essential AWS functionality you need without the complexity or cost of paid alternatives.

## Why Nimbus?

**Nimbus is built for developers who want:**
- 🆓 **Free** - No subscriptions, no feature paywalls
- ⚡ **Fast** - Real AWS Lambda containers, not slow emulation
- 🎯 **Practical** - Focus on the 80% of AWS features you actually use
- 🔧 **Simple** - Docker Compose setup, works in minutes

### What's Supported

| Service | Features | Status |
|---------|----------|--------|
| **Lambda** | Create/update/delete/invoke, ZIP & Docker images, real runtime environment | ✅ Full |
| **ECR** | Push/pull images, repositories, authentication | ✅ Full |
| **SQS** | Queues, messages, dead-letter queues, FIFO | ✅ Full |
| **Event Source Mapping** | SQS → Lambda triggers, batch processing | ✅ Full |
| **S3** | Basic operations (via MinIO) | ✅ Basic |
| **SSM Parameter Store** | Parameters, versions, encryption | ✅ Full |
| **CloudWatch Logs** | Log groups/streams, filtering | ✅ Full |

### Comparison with Alternatives

| Feature | Nimbus | LocalStack Free | LocalStack Pro |
|---------|--------|-----------------|----------------|
| Lambda (ZIP) | ✅ | ✅ | ✅ |
| Lambda (ECR/Docker) | ✅ | ❌ | ✅ |
| Real Lambda runtime | ✅ | ❌ | ✅ |
| SQS + Lambda triggers | ✅ | ⚠️ Limited | ✅ |
| S3 (basic operations) | ✅ | ✅ | ✅ |
| ECR | ✅ | ❌ | ✅ |
| SSM Parameter Store | ✅ | ⚠️ Basic | ✅ |
| CloudWatch Logs | ✅ | ⚠️ Basic | ✅ |
| Cost | **Free** | Free | **$$$** |

## Quick Start

### Prerequisites
- Docker & Docker Compose
- AWS CLI

### 1. Start Nimbus

Create the docker network manually
```
docker network create localcloud
```

Start the system
```bash
docker compose up -d
```

That's it! Services are now running on `localhost:4566` with web console for basic AWS Console for quick view of services

### 2. Configure AWS CLI

Create a profile for Nimbus:

```bash
# Option 1: Interactive
aws configure --profile nimbus
# AWS Access Key ID: localcloud
# AWS Secret Access Key: localcloud
# Default region: ap-southeast-2
# Default output format: json

# Option 2: Direct config
cat <<EOF >> ~/.aws/credentials
[localcloud]
aws_access_key_id = localcloud
aws_secret_access_key = localcloud
EOF

cat <<EOF >> ~/.aws/config
[profile localcloud]
region = ap-southeast-2
output = json
endpoint_url = http://localhost:4566
EOF
```

### 3. Set your profile

```bash
export AWS_PROFILE=localcloud
```

### 4. Test it works

```bash
# Create a simple Lambda function
cat > lambda_function.py << 'EOF'
def handler(event, context):
    return {'statusCode': 200, 'body': 'Hello from Nimbus!'}
EOF

zip function.zip lambda_function.py

aws lambda create-function \
  --function-name hello-nimbus \
  --runtime python3.11 \
  --handler lambda_function.handler \
  --zip-file fileb://function.zip \
  --role arn:aws:iam::000000000000:role/lambda-role

# Invoke it
aws lambda invoke \
  --function-name hello-nimbus \
  --payload '{"name": "World"}' \
  --cli-binary-format raw-in-base64-out \
  response.json

cat response.json
```
> Output

```json
{"statusCode": 200, "body": "Hello from Nimbus!"}
```

## Common Use Cases

### Lambda Functions

#### From ZIP file
```bash
# Create function
cat > lambda_function.py << 'EOF'
def handler(event, context):
    return {'statusCode': 200, 'body': 'Hello to Freedom!'}
EOF
zip function.zip lambda_function.py
aws lambda create-function \
  --function-name my-function \
  --runtime python3.11 \
  --handler lambda_function.handler \
  --zip-file fileb://function.zip \
  --role arn:aws:iam::000000000000:role/lambda-role

# Update code
aws lambda update-function-code \
  --function-name my-function \
  --zip-file fileb://function.zip

# Invoke
aws lambda invoke \
  --function-name my-function \
  --payload '{"key": "value"}' \
  --cli-binary-format raw-in-base64-out \
  response.json

# Check response
cat response.json
```
>Output

```json
{"statusCode": 200, "body": "Hello to Freedom!"}
```

#### From Docker image
```bash
# Create a simple Dockerfile with your function
cat > Dockerfile << 'EOF'
FROM public.ecr.aws/lambda/python:3.11
COPY lambda_function.py ${LAMBDA_TASK_ROOT}
CMD [ "lambda_function.handler" ]
EOF

cat > lambda_function.py << 'EOF'
def handler(event, context):
    return {'statusCode': 200, 'body': 'Hello from Docker!'}
EOF

# Build the image
docker build -t my-lambda:latest .

# Tag for local ECR
docker tag my-lambda:latest localhost:5000/my-lambda:latest

# Push to local ECR registry
docker push localhost:5000/my-lambda:latest

# Create function from your image
aws lambda create-function \
  --function-name my-container-function \
  --package-type Image \
  --code ImageUri=my-lambda:latest \
  --role arn:aws:iam::000000000000:role/lambda-role

# Invoke it
aws lambda invoke \
  --function-name my-container-function \
  --payload '{"key": "value"}' \
  --cli-binary-format raw-in-base64-out \
  response.json

cat response.json
```
> Output

```json
{"statusCode": 200, "body": "Hello from Docker!"}
```

### SQS Queues

```bash
# Create queue
queueUrl=$(aws sqs create-queue --queue-name my-queue| jq -r '.QueueUrl')

# Send message
aws sqs send-message \
  --queue-url $queueUrl \
  --message-body "Hello from SQS"

# Receive messages
aws sqs receive-message \
  --queue-url $queueUrl
```

### SQS → Lambda Triggers

```bash
# Create event source mapping
aws lambda create-event-source-mapping \
  --function-name my-function \
  --event-source-arn arn:aws:sqs:ap-southeast-2:456645664566:my-queue \
  --batch-size 10

# Messages sent to the queue will automatically trigger your Lambda
```

### SSM Parameters

```bash
# Store parameter
aws ssm put-parameter \
  --name /myapp/database/password \
  --value "secret123" \
  --type SecureString

# Retrieve parameter
aws ssm get-parameter \
  --name /myapp/database/password \
  --with-decryption
```

### CloudWatch Logs

```bash
# View logs for a Lambda function
aws logs filter-log-events \
  --log-group-name /aws/lambda/my-function
```

## Performance

### Lambda Cold Start
```bash
$ time aws lambda invoke --function-name my-function \
  --payload '{}' --cli-binary-format raw-in-base64-out response.json

real    0m1.223s  # First invocation (container startup)
```

### Lambda Warm Start (Almost no difference)
```bash
$ time aws lambda invoke --function-name my-function \
  --payload '{}' --cli-binary-format raw-in-base64-out response.json

real    0m1.193s  # Subsequent invocations (container reuse)
```

## Testing

Run the included test suite:

```bash
cd tests

# Test all runtimes
(cd ecr && ./test.sh) && \
(cd nodejs && ./test.sh) && \
(cd python && ./test.sh) && \
(cd rust && ./test.sh) && \
echo "ALL TESTS PASSED!"
```

## Debugging

```bash
# View all logs
docker compose logs -f

# View specific service
docker compose logs -f lambda

# View Lambda container logs
docker logs localcloud-lambda-{function-name}-{instance-id}
```

## Architecture

Nimbus uses a microservices architecture with dedicated containers for each AWS service:

- **API Gateway** (`api`) - Routes requests to appropriate services
- **Lambda** (`lambda`) - Container lifecycle management, invocations
- **ECR** (`ecr`) - Docker registry (port 5000)
- **SQS** (`sqs`) - Message queuing
- **Event Source Mapping** (`esm`) - Trigger management
- **S3** (`s3`) - Object storage (MinIO)

All services communicate via Docker networking and expose a unified API on `localhost:4566`.

## Advanced Configuration

### Environment Variables

```bash
# docker-compose.yml
environment:
  - AWS_REGION=ap-southeast-2
  - AWS_ACCOUNT_ID=456645664566
  - STORAGE_PATH=/data  # Persist data between restarts
```

### Data Persistence

Nimbus stores data in Docker volumes:
- Lambda functions: `./data/lambda-functions`
- Databases: `./data/*.db`
- S3 objects: MinIO volume

## What's Missing?

Nimbus focuses on **development workflows**, not completely production feature parity. Not included:

- ❌ IAM permissions (all operations allowed)
- ❌ VPC/networking simulation
- ❌ CloudFormation
- ❌ Step Functions
- ❌ Advanced S3 features (versioning, lifecycle policies.... yet)
- ❌ API Gateway (use Lambda invoke directly)

**This is intentional.** These features add complexity that most developers don't need for local testing.

## Contributing

Nimbus is open source and contributions are welcome, send a PR with unittests! The codebase is designed to be readable and modular:

- `aws_api.py` - Main API gateway and routing, built in S3 proxying and simple SSM support.
- `lambda/main.py` - Lambda container lifecycle
- `sqs/main.py` - SQS implementation
- `esm/main.py` - Event source mapping

## License

MIT - Use freely for any purpose,

---

**Built by freendom for developers who want simple, free AWS emulation**
