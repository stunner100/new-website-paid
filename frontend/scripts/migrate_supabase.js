// Migrate local uploads into Supabase and update DB storage_key when needed
// Requirements: env SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_BUCKET (default: videos), DATABASE_URL
// Run from repo root or frontend: `node new-website-paid/frontend/scripts/migrate_supabase.js`

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');
const { createClient } = require('@supabase/supabase-js');

function loadEnvFile(envPath) {
  try {
    if (!fs.existsSync(envPath)) return;
    const content = fs.readFileSync(envPath, 'utf8');
    for (const line of content.split(/\r?\n/)) {
      const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
      if (!m) continue;
      const key = m[1];
      let val = m[2];
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith('\'') && val.endsWith('\''))) {
        val = val.slice(1, -1);
      }
      if (process.env[key] === undefined) {
        process.env[key] = val;
      }
    }
    console.log(`Loaded env from ${envPath}`);
  } catch (e) {
    console.warn(`Failed to load env ${envPath}:`, e.message || e);
  }
}

function ensureEnv(name) {
  const val = process.env[name];
  if (!val) throw new Error(`Missing required env: ${name}`);
  return val;
}

function guessContentType(filename) {
  const lower = filename.toLowerCase();
  if (lower.endsWith('.mp4')) return 'video/mp4';
  if (lower.endsWith('.mov')) return 'video/quicktime';
  if (lower.endsWith('.avi')) return 'video/x-msvideo';
  if (lower.endsWith('.mkv')) return 'video/x-matroska';
  return 'application/octet-stream';
}

async function main() {
  const SUPABASE_URL = ensureEnv('SUPABASE_URL');
  const SUPABASE_SERVICE_ROLE_KEY = ensureEnv('SUPABASE_SERVICE_ROLE_KEY');
  const SUPABASE_BUCKET = process.env.SUPABASE_BUCKET || 'videos';
  const DATABASE_URL = ensureEnv('DATABASE_URL');

  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
  const pg = new Client({ connectionString: DATABASE_URL });
  await pg.connect();

  // uploads directory: two levels up from this script file into project root
  // Try to pull envs from common local locations if not provided
  // Frontend .env
  loadEnvFile(path.resolve(__dirname, '../.env'));
  // Project root .env
  loadEnvFile(path.resolve(__dirname, '../../.env'));

  const uploadsDir = path.resolve(__dirname, '../../uploads');
  if (!fs.existsSync(uploadsDir)) {
    throw new Error(`Uploads directory not found at ${uploadsDir}`);
  }

  const { rows } = await pg.query('select id, storage_key, uploader_id from videos order by id asc');
  let total = 0, uploaded = 0, skipped = 0, updatedKeys = 0, missing = 0, failed = 0;

  for (const v of rows) {
    total++;
    const { id, storage_key, uploader_id } = v;

    // Determine local file path (support new and legacy formats)
    let candidatePaths = [];
    candidatePaths.push(path.join(uploadsDir, storage_key));
    const base = storage_key.includes('/') ? storage_key.split('/').pop() : storage_key;
    candidatePaths.push(path.join(uploadsDir, base));
    if (!storage_key.includes('/')) {
      candidatePaths.push(path.join(uploadsDir, String(uploader_id), base));
    }

    const localPath = candidatePaths.find(p => fs.existsSync(p));
    if (!localPath) {
      console.warn(`[${id}] Missing local file for storage_key=${storage_key}`);
      missing++;
      continue;
    }

    // Decide Supabase object key
    const newKey = storage_key.includes('/') ? storage_key : `${uploader_id}/${storage_key}`;
    const needsUpdate = newKey !== storage_key;

    // Read file and upload
    try {
      const data = fs.readFileSync(localPath);
      const contentType = guessContentType(localPath);
      const { error } = await sb.storage.from(SUPABASE_BUCKET).upload(newKey, data, {
        contentType,
        upsert: true,
      });
      if (error) {
        console.error(`[${id}] Upload failed:`, error.message);
        failed++;
        continue;
      }
      uploaded++;

      if (needsUpdate) {
        await pg.query('update videos set storage_key=$1, updated_at=now() where id=$2', [newKey, id]);
        updatedKeys++;
        console.log(`[${id}] Updated storage_key -> ${newKey}`);
      } else {
        console.log(`[${id}] Uploaded using existing key ${newKey}`);
      }
    } catch (e) {
      console.error(`[${id}] Migration error:`, e.message || e);
      failed++;
    }
  }

  console.log('\nMigration summary');
  console.log('-----------------');
  console.log(`Total videos: ${total}`);
  console.log(`Uploaded:     ${uploaded}`);
  console.log(`Missing:      ${missing}`);
  console.log(`Failed:       ${failed}`);
  console.log(`Keys updated: ${updatedKeys}`);

  await pg.end();
}

main().catch((e) => {
  console.error('Fatal migration error:', e.message || e);
  process.exit(1);
});