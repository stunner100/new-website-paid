// Update R2 bucket CORS via S3-compatible API
// Usage: node scripts/set_r2_cors.js
// Requires env vars: R2_ENDPOINT, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET

const { S3Client, PutBucketCorsCommand, GetBucketCorsCommand } = require('@aws-sdk/client-s3');
const fs = require('fs');
const path = require('path');

function loadRootEnv() {
  try {
    const candidates = [
      path.resolve(__dirname, '..', '.env'),       // frontend/.env
      path.resolve(__dirname, '..', '..', '.env'), // project/.env
    ];
    for (const envPath of candidates) {
      if (fs.existsSync(envPath)) {
        const content = fs.readFileSync(envPath, 'utf8');
        content.split(/\r?\n/).forEach((line) => {
          if (!line || /^\s*#/.test(line)) return;
          const i = line.indexOf('=');
          if (i === -1) return;
          const k = line.slice(0, i).trim();
          const v = line.slice(i + 1).trim();
          if (!(k in process.env)) process.env[k] = v;
        });
      }
    }
  } catch {}
}

async function main() {
  loadRootEnv();
  const endpoint = process.env.R2_ENDPOINT;
  const accessKeyId = process.env.R2_ACCESS_KEY_ID;
  const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;
  const bucket = process.env.R2_BUCKET;
  if (!endpoint || !accessKeyId || !secretAccessKey || !bucket) {
    console.error('Missing R2 config. Ensure R2_ENDPOINT, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET are set.');
    process.exit(1);
  }

  const s3 = new S3Client({
    region: 'auto',
    endpoint,
    credentials: { accessKeyId, secretAccessKey },
  });

  const AllowedOrigins = [
    'https://bluefilmx.com',
    'https://www.bluefilmx.com',
    'https://production.bluefilmx.pages.dev',
  ];
  const AllowedMethods = ['PUT', 'GET', 'HEAD', 'POST', 'DELETE'];
  const AllowedHeaders = ['*'];
  const ExposeHeaders = ['ETag', 'Content-Type'];
  const MaxAgeSeconds = 86400;

  const corsConfig = {
    CORSRules: [
      {
        AllowedOrigins,
        AllowedMethods,
        AllowedHeaders,
        ExposeHeaders,
        MaxAgeSeconds,
      },
    ],
  };

  try {
    // Log existing CORS (if any)
    try {
      const current = await s3.send(new GetBucketCorsCommand({ Bucket: bucket }));
      console.log('Current CORS:', JSON.stringify(current?.CORSConfiguration || {}, null, 2));
    } catch (e) {
      console.log('No existing CORS or failed to read (continuing)...');
    }

    await s3.send(new PutBucketCorsCommand({ Bucket: bucket, CORSConfiguration: corsConfig }));
    console.log('✅ Updated R2 CORS for bucket:', bucket);
  } catch (err) {
    console.error('❌ Failed to update R2 CORS:', err?.message || err);
    process.exit(1);
  }
}

main();
