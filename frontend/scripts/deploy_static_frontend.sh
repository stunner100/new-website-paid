#!/bin/bash

set -euo pipefail

if [[ $# -lt 2 ]]; then
  cat <<'USAGE'
Usage: ./scripts/deploy_static_frontend.sh <project_id> <bucket>

Arguments:
  project_id   GCP project identifier
  bucket       Cloud Storage bucket for static site (without gs://)

Environment variables:
  REGION             Default us-central1 (for Cloud CDN invalidation)
  BUILD_DIR          Default build
  CDN_URL_MAP        Optional URL map name for CDN cache invalidation
USAGE
  exit 1
fi

PROJECT_ID=$1
BUCKET=$2

REGION=${REGION:-us-central1}
BUILD_DIR=${BUILD_DIR:-build}
CDN_URL_MAP=${CDN_URL_MAP:-}

if [[ ! -d "$BUILD_DIR" ]]; then
  echo "Build directory '$BUILD_DIR' not found. Run npm run build first." >&2
  exit 1
fi

gcloud config set project "$PROJECT_ID"

echo "Uploading static assets to gs://${BUCKET}..."
gsutil -m rsync -r "$BUILD_DIR" "gs://${BUCKET}"

echo "Setting cache headers for static assets..."
while IFS= read -r -d '' file; do
  object_path=${file#${BUILD_DIR}/}
  gsutil setmeta -h "Cache-Control: no-cache" "gs://${BUCKET}/${object_path}"
done < <(find "$BUILD_DIR" -type f -name '*.html' -print0)

while IFS= read -r -d '' file; do
  object_path=${file#${BUILD_DIR}/}
  gsutil setmeta -h "Cache-Control: public, max-age=31536000, immutable" "gs://${BUCKET}/${object_path}"
done < <(find "$BUILD_DIR" -type f ! -name '*.html' -print0)

if [[ -n "$CDN_URL_MAP" ]]; then
  echo "Invalidating Cloud CDN cache for /*"
  gcloud compute url-maps invalidate-cdn-cache "$CDN_URL_MAP" --path "/*" --async
fi

echo "Frontend deployment completed."

