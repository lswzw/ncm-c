#!/bin/bash
set -e

# Image name
IMAGE_NAME="ncm-builder"
CONTAINER_NAME="ncm-temp-container"

echo "Building Docker image..."
docker build -t $IMAGE_NAME .

echo "Creating temporary container..."
docker create --name $CONTAINER_NAME $IMAGE_NAME

echo "Extracting artifacts..."
mkdir -p output
docker cp $CONTAINER_NAME:/app/build/linux/ncm-linux ./output/
docker cp $CONTAINER_NAME:/app/build/windows/ncm-windows.exe ./output/

echo "Cleaning up..."
docker rm $CONTAINER_NAME

echo "Build complete! Artifacts are in the 'output' directory."
ls -l output/
