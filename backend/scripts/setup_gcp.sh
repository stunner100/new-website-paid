#!/bin/bash

set -euo pipefail

if [[ $# -lt 3 ]]; then
  cat <<'USAGE'
Usage: ./scripts/setup_gcp.sh <project_id> <domain> <dns_zone>

Arguments:
  project_id   GCP project identifier
  domain       Root domain (e.g., example.com)
  dns_zone     DNS zone name to create/manage (e.g., mediavid-zone)

Environment variables (optional overrides):
  REGION                 Default us-central1
  BACKEND_SERVICE_NAME   Default mediavid-api
  FRONTEND_BUCKET        Default ${PROJECT_ID}-frontend
  MEDIA_BUCKET           Default ${PROJECT_ID}-media
  ARTIFACT_REGISTRY      Default backend
  CORS_TEMPLATE          Path to CORS JSON template (default scripts/cors.json)
USAGE
  exit 1
fi

PROJECT_ID=$1
DOMAIN=$2
DNS_ZONE=$3

REGION=${REGION:-us-central1}
BACKEND_SERVICE_NAME=${BACKEND_SERVICE_NAME:-mediavid-api}
FRONTEND_BUCKET=${FRONTEND_BUCKET:-${PROJECT_ID}-frontend}
MEDIA_BUCKET=${MEDIA_BUCKET:-${PROJECT_ID}-media}
ARTIFACT_REGISTRY=${ARTIFACT_REGISTRY:-backend}
CORS_TEMPLATE=${CORS_TEMPLATE:-$(dirname "$0")/cors.json}

if [[ ! -f "$CORS_TEMPLATE" ]]; then
  echo "CORS template file not found: $CORS_TEMPLATE" >&2
  exit 1
fi

gcloud config set project "$PROJECT_ID"

echo "Enabling required APIs..."
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  compute.googleapis.com \
  dns.googleapis.com \
  secretmanager.googleapis.com \
  certificatemanager.googleapis.com \
  cloudresourcemanager.googleapis.com

echo "Creating Artifact Registry..."
gcloud artifacts repositories describe "$ARTIFACT_REGISTRY" --location="$REGION" >/dev/null 2>&1 || \
  gcloud artifacts repositories create "$ARTIFACT_REGISTRY" \
    --repository-format=docker \
    --location="$REGION" \
    --description="Backend service images"

echo "Creating Cloud Storage buckets..."
gsutil ls -b "gs://${FRONTEND_BUCKET}" >/dev/null 2>&1 || gsutil mb -l "$REGION" "gs://${FRONTEND_BUCKET}"
gsutil ls -b "gs://${MEDIA_BUCKET}" >/dev/null 2>&1 || gsutil mb -l "$REGION" "gs://${MEDIA_BUCKET}"
gsutil uniformbucketlevelaccess set on "gs://${FRONTEND_BUCKET}"
gsutil uniformbucketlevelaccess set on "gs://${MEDIA_BUCKET}"

echo "Setting CORS on media bucket from template..."
# Replace placeholder domain tokens in template before applying
TMP_CORS=$(mktemp)
sed "s/https:\/\/example.com/https:\/\/${DOMAIN}/g" "$CORS_TEMPLATE" |
  sed "s/https:\/\/www.example.com/https:\/\/www.${DOMAIN}/g" > "$TMP_CORS"
gsutil cors set "$TMP_CORS" "gs://${MEDIA_BUCKET}"
rm "$TMP_CORS"

echo "Configuring DNS zone..."
gcloud dns managed-zones describe "$DNS_ZONE" >/dev/null 2>&1 || \
  gcloud dns managed-zones create "$DNS_ZONE" \
    --dns-name="$DOMAIN." \
    --description="Managed zone for ${DOMAIN}"

echo "Requesting managed certificate for frontend..."
gcloud certificate-manager certificates create "${DOMAIN//./-}-frontend" \
  --domains="${DOMAIN},www.${DOMAIN}" \
  --project="$PROJECT_ID"

echo "Setup script completed. Review Cloud DNS name servers and update at registrar if needed."

