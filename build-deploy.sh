
# localcloud-sqs-backend-1
version=1.0.0
docker build -t localcloud/sqs-backend:$version -f src/sqs/Dockerfile-backend src/sqs/
docker tag localcloud/sqs-backend:$version image-registry.global.emperor-it.com/eit/localcloud/sqs-backend:$version
docker push image-registry.global.emperor-it.com/eit/localcloud/sqs-backend:$version

# localcloud-sqs-1
version=1.0.0
docker build -t localcloud/sqs:$version -f src/sqs/Dockerfile-sqs ./src/sqs/
docker tag localcloud/sqs:$version image-registry.global.emperor-it.com/eit/localcloud/sqs:$version
docker push image-registry.global.emperor-it.com/eit/localcloud/sqs:$version

# localcloud-lambda-1
version=1.0.0
docker build -t localcloud/lambda:$version -f src/lambda/Dockerfile ./src/lambda/
docker tag localcloud/lambda:$version image-registry.global.emperor-it.com/eit/localcloud/lambda:$version
docker push image-registry.global.emperor-it.com/eit/localcloud/lambda:$version

# localcloud-esm-1
version=1.0.0
docker build -t localcloud/esm:$version -f src/event-source-mapping/Dockerfile ./src/event-source-mapping/
docker tag localcloud/esm:$version image-registry.global.emperor-it.com/eit/localcloud/esm:$version
docker push image-registry.global.emperor-it.com/eit/localcloud/esm:$version

# localcloud-api-1
version=1.0.0
docker build -t localcloud/api:$version -f aws-api/Dockerfile.api ./aws-api/
docker tag localcloud/api:$version image-registry.global.emperor-it.com/eit/localcloud/api:$version
docker push image-registry.global.emperor-it.com/eit/localcloud/api:$version


