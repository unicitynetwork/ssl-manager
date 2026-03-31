#!/bin/bash

# Build and push ssl-manager Docker image to GitHub Container Registry
# Usage: ./publish.sh [tag]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="ssl-manager"
TAG="${1:-latest}"
REGISTRY="${SSL_MANAGER_REGISTRY:-ghcr.io/unicitynetwork}"
FULL_IMAGE="${REGISTRY}/${IMAGE_NAME}"

echo "============================================"
echo "   ssl-manager Docker Image Publisher"
echo "============================================"
echo ""
echo "Image: ${FULL_IMAGE}:${TAG}"
echo ""

# Check Docker
if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker is not running" >&2
    exit 1
fi

# Check GHCR login
if [[ "${FULL_IMAGE}" == ghcr.io/* ]]; then
    if ! docker info 2>/dev/null | grep -q "ghcr.io"; then
        echo "WARNING: You may not be logged in to GitHub Container Registry"
        echo ""
        echo "To login:"
        echo "  echo \${GITHUB_PAT} | docker login ghcr.io -u USERNAME --password-stdin"
        echo ""
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo ""
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi
fi

# Build
echo "Building ${FULL_IMAGE}:${TAG}..."
docker build -t "${FULL_IMAGE}:${TAG}" "${SCRIPT_DIR}"

# Also tag as latest
if [ "${TAG}" != "latest" ]; then
    docker tag "${FULL_IMAGE}:${TAG}" "${FULL_IMAGE}:latest"
fi

# Also tag as ssl-manager:latest locally (for downstream builds)
docker tag "${FULL_IMAGE}:${TAG}" "ssl-manager:latest"

IMAGE_SIZE=$(docker images --format "{{.Size}}" "${FULL_IMAGE}:${TAG}")
echo ""
echo "Build successful (${IMAGE_SIZE})"

# Push
echo ""
echo "Tags to push:"
echo "  ${FULL_IMAGE}:${TAG}"
[ "${TAG}" != "latest" ] && echo "  ${FULL_IMAGE}:latest"
echo ""
read -p "Push to registry? [y/N] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker push "${FULL_IMAGE}:${TAG}"
    [ "${TAG}" != "latest" ] && docker push "${FULL_IMAGE}:latest"
    echo ""
    echo "Pushed: ${FULL_IMAGE}:${TAG}"
    echo ""
    echo "Other projects can now use:"
    echo "  FROM ${FULL_IMAGE}:${TAG}"
else
    echo "Push cancelled. Image available locally as:"
    echo "  ${FULL_IMAGE}:${TAG}"
    echo "  ssl-manager:latest"
fi
