# Configure Cloudflare R2 CORS for Direct Uploads

## Current Status: Server-Side Upload Active

Your uploads are currently working via server-side processing to avoid CORS issues. To enable faster direct browser uploads, configure CORS as described below.

## The Problem

The `net::ERR_FAILED` and `TypeError: Failed to fetch` errors indicate that your R2 bucket doesn't allow browser uploads from your domain due to missing CORS configuration.

## Option 1: Cloudflare Dashboard (Recommended)

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Navigate to R2 Object Storage → Your bucket (`bluevideos`)
3. Go to Settings → CORS policy
4. Add this CORS configuration:

```json
[
  {
    "AllowedOrigins": [
      "https://bluefilmx.com",
      "https://*.netlify.app",
      "http://localhost:8888",
      "http://localhost:3000"
    ],
    "AllowedMethods": [
      "GET",
      "PUT",
      "POST",
      "DELETE",
      "HEAD",
      "OPTIONS"
    ],
    "AllowedHeaders": [
      "*",
      "Content-Type",
      "Content-Length",
      "Authorization",
      "x-amz-content-sha256",
      "x-amz-date",
      "x-amz-security-token"
    ],
    "ExposeHeaders": [
      "ETag",
      "Content-Length",
      "Content-Type",
      "x-amz-version-id"
    ],
    "MaxAgeSeconds": 86400
  }
]
```

## Alternative Simplified CORS (Try this if the above doesn't work)

```json
[
  {
    "AllowedOrigins": ["*"],
    "AllowedMethods": ["GET", "PUT", "POST", "DELETE", "HEAD", "OPTIONS"],
    "AllowedHeaders": ["*"],
    "ExposeHeaders": ["*"],
    "MaxAgeSeconds": 86400
  }
]
```

## Option 2: Using Wrangler CLI

If you have Wrangler installed:

```bash
# Install wrangler if you haven't
npm install -g wrangler

# Login to Cloudflare
wrangler login

# Create cors.json file with the above configuration
# Then apply it:
wrangler r2 bucket cors put bluevideos --file cors.json
```

## Option 3: Server-Side Upload Only

If you prefer to skip CORS setup, the app will automatically fall back to server-side uploads, which work without CORS configuration. The fallback is already implemented in your upload flow.

## Test After CORS Setup

Once CORS is configured:
1. Go to https://bluefilmx.com
2. Register/login and get admin access
3. Try uploading a video - it should now work with direct R2 upload
4. Check your R2 bucket to confirm the file was uploaded

## Current Fallback

Your app already handles CORS failures gracefully:
- If direct upload fails → automatically uses server-side upload
- Server-side upload always works (no CORS needed)
- Files still end up in the same R2 bucket with the same naming scheme