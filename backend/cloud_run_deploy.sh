#!/bin/bash

set -euo pipefail

if [[ -z "${PROJECT_ID:-}" ]]; then
  echo "PROJECT_ID environment variable is required" >&2
  exit 1
fi

REGION=${REGION:-us-central1}
SERVICE_NAME=${SERVICE_NAME:-mediavid-api}
ARTIFACT_REGISTRY=${ARTIFACT_REGISTRY:-backend}
IMAGE_TAG=${IMAGE_TAG:-prod}

gcloud config set project "$PROJECT_ID"
gcloud artifacts repositories describe "$ARTIFACT_REGISTRY" --location="$REGION" >/dev/null 2>&1 || \
  gcloud artifacts repositories create "$ARTIFACT_REGISTRY" --repository-format=docker --location="$REGION" --description="Backend service images"

IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${ARTIFACT_REGISTRY}/${SERVICE_NAME}:${IMAGE_TAG}"

echo "Building Docker image..."
gcloud builds submit --tag "$IMAGE" ..

echo "Deploying to Cloud Run..."
gcloud run deploy "$SERVICE_NAME" \
  --image "$IMAGE" \
  --platform managed \
  --region "$REGION" \
  --allow-unauthenticated \
  --port 8080

echo "Deployment completed."

