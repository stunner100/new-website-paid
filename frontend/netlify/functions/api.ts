import { Handler } from "@netlify/functions";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Client } from "pg";
// NEW: storage and upload utils
import Busboy from "busboy";
import { createClient } from "@supabase/supabase-js";
import { randomUUID } from "crypto";
import { writeFileSync, mkdirSync, existsSync, readFileSync } from "fs";
import { join } from "path";

// Prefer Netlify's injected Neon connection, fall back to local DATABASE_URL
const DATABASE_URL = (process.env.NETLIFY_DATABASE_URL || process.env.DATABASE_URL) as string;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
// NEW: Supabase envs
const SUPABASE_URL = process.env.SUPABASE_URL as string;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY as string;
const SUPABASE_BUCKET = process.env.SUPABASE_BUCKET || "videos";
const R2_ENDPOINT = process.env.R2_ENDPOINT as string;
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID as string;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY as string;
const R2_BUCKET = process.env.R2_BUCKET || "videos";
const DEV_ALLOW_ELEVATION = process.env.DEV_ALLOW_ELEVATION === "true";
const STORAGE_BACKEND = (process.env.STORAGE_BACKEND || "auto").toLowerCase();

function json(statusCode: number, body: any, headers: Record<string, string> = {}) {
  return {
    statusCode,
    headers: { 
      "content-type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      ...headers 
    },
    body: JSON.stringify(body),
  };
}

async function getClient() {
  if (!DATABASE_URL) {
    throw new Error("DATABASE_URL is not set");
  }
  const client = new Client({
    connectionString: DATABASE_URL,
    ssl: /localhost|127.0.0.1/.test(DATABASE_URL) ? false : { rejectUnauthorized: false },
  } as any);
  await client.connect();
  return client;
}

// NEW: Supabase client factory
function getSupabase() {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error("Supabase environment variables are not set");
  }
  return createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
}

// UPDATED: ensureSchema also creates videos table
async function ensureSchema() {
  const client = await getClient();
  try {
    await client.query(`
      create table if not exists users (
        id bigserial primary key,
        email text unique not null,
        name text not null,
        password_hash text not null,
        age_verified boolean default false,
        is_admin boolean default false,
        is_approved boolean default false,
        created_at timestamptz default now()
      );

      create table if not exists videos (
        id bigserial primary key,
        title text not null,
        description text not null,
        category text not null,
        tags text[] default '{}',
        status text not null default 'pending', -- pending | approved | rejected
        views bigint not null default 0,
        uploader_id bigint references users(id) on delete set null,
        storage_key text not null,
        created_at timestamptz default now(),
        updated_at timestamptz default now()
      );
    `);
  } finally {
    await client.end();
  }
}

function signToken(payload: object) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
}

function getPath(path: string) {
  // Normalize to ensure "/.netlify/functions/api/..." -> "/api/..."
  const idx = path.indexOf("/api/");
  return idx >= 0 ? path.slice(idx) : path;
}

// NEW: auth helpers
async function getUserById(userId: number) {
  const client = await getClient();
  try {
    const { rows } = await client.query(
      `select id, email, name, age_verified, is_admin, is_approved from users where id=$1`,
      [userId]
    );
    return rows[0];
  } finally {
    await client.end();
  }
}

async function requireAuth(event: any): Promise<{ userId: number; is_admin: boolean; user: any }> {
  const auth = (event.headers?.authorization || event.headers?.Authorization || "") as string;
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : (event.queryStringParameters?.token as string | undefined);
  if (!token) throw new Error("Unauthorized");
  const payload = jwt.verify(token, JWT_SECRET) as any;
  const userId = Number(payload.sub);
  if (!userId) throw new Error("Unauthorized");
  const user = await getUserById(userId);
  if (!user) throw new Error("Unauthorized");
  return { userId, is_admin: !!user.is_admin, user };
}

async function requireAdmin(event: any) {
  const auth = await requireAuth(event);
  if (!auth.is_admin) throw new Error("Forbidden");
  return auth;
}

// NEW: multipart parser for Netlify Functions
function parseMultipart(event: any): Promise<{ fields: Record<string, string>; file?: { filename: string; mimetype: string; data: Buffer } }> {
  return new Promise((resolve, reject) => {
    const contentType = (event.headers["content-type"] || event.headers["Content-Type"]) as string;
    if (!contentType || !contentType.startsWith("multipart/form-data")) {
      return reject(new Error("Invalid content type"));
    }
    const bb = Busboy({ headers: { "content-type": contentType } } as any);

    const fields: Record<string, string> = {};
    let theFile: { filename: string; mimetype: string; data: Buffer } | undefined;

    bb.on("field", (name: string, val: string) => {
      fields[name] = val;
    });

    bb.on("file", (_name: string, file: any, info: any) => {
      const { filename, mimeType } = info;
      const chunks: Buffer[] = [];
      file.on("data", (d: Buffer) => chunks.push(d));
      file.on("end", () => {
        theFile = { filename, mimetype: mimeType, data: Buffer.concat(chunks) };
      });
    });

    bb.on("error", (err: any) => reject(err));
    bb.on("finish", () => resolve({ fields, file: theFile }));

    const body = Buffer.from(event.body || "", event.isBase64Encoded ? "base64" : "utf8");
    bb.end(body);
  });
}

function sanitizeFilename(name: string) {
  return name.replace(/[^a-zA-Z0-9._-]/g, "_");
}

export const handler: Handler = async (event) => {
  try {
    const method = event.httpMethod;
    const path = getPath(event.path || "/");

    // Handle CORS preflight requests
    if (method === "OPTIONS") {
      return json(200, {});
    }

    if (method === "GET" && path === "/api/health") {
      try {
        const client = await getClient();
        try {
          const { rows } = await client.query("select 1 as db");
          return json(200, { ok: true, db: rows?.[0]?.db === 1 });
        } finally {
          await client.end();
        }
      } catch {
        return json(200, { ok: true, db: false });
      }
    }

    // Direct-to-R2: request presigned PUT URL
    if (method === "POST" && path === "/api/uploads/presign") {
      try {
        await ensureSchema();
        const { userId } = await requireAdmin(event);
        if (!useR2()) {
          return json(400, { detail: "R2 not configured" });
        }
        const body = event.body ? JSON.parse(event.body) : {};
        const rawName = (body.filename || "upload.mp4").toString();
        const contentType = (body.contentType || "application/octet-stream").toString();
        const safeName = sanitizeFilename(rawName);
        const storageKey = `${userId}/${randomUUID()}_${safeName}`;

        const s3 = await getS3();
        const { PutObjectCommand } = await import("@aws-sdk/client-s3");
        const { getSignedUrl } = await import("@aws-sdk/s3-request-presigner");
        const cmd = new PutObjectCommand({
          Bucket: R2_BUCKET,
          Key: storageKey
        });
        const uploadUrl = await getSignedUrl(s3, cmd, { expiresIn: 60 * 10 });
        
        console.log("Generated presigned URL for:", storageKey);
        console.log("URL domain:", new URL(uploadUrl).hostname);
        
        return json(200, {
          uploadUrl,
          storageKey,
          debug: {
            bucket: R2_BUCKET,
            endpoint: R2_ENDPOINT,
            storageKey,
            contentType
          },
          corsNote: "If upload fails with CORS error, configure R2 bucket CORS to allow your domain"
        });
      } catch (e: any) {
        console.error("Presign error:", e);
        const code = e?.message === "Unauthorized" ? 401 : e?.message === "Forbidden" ? 403 : 500;
        return json(code, { detail: e?.message || "Failed to presign", error: e?.stack });
      }
    }

    if (method === "POST" && path === "/api/auth/register") {
      const body = event.body ? JSON.parse(event.body) : {};
      const { email, name, password, age_verified } = body || {};
      if (!email || !name || !password) return json(400, { detail: "Missing fields" });
      await ensureSchema();
      const client = await getClient();
      try {
        const password_hash = await bcrypt.hash(password, 10);
        const { rows } = await client.query(
          `insert into users (email, name, password_hash, age_verified, is_admin, is_approved)
           values ($1,$2,$3,$4,$5,$6)
           returning id, email, name, age_verified, is_admin, is_approved`,
          [email, name, password_hash, !!age_verified, false, false]
        );
        const user = rows[0];
        const token = signToken({ sub: user.id });
        return json(200, { access_token: token, token_type: "bearer", user });
      } catch (e: any) {
        if (e.code === "23505") return json(400, { detail: "Email already registered" });
        return json(500, { detail: "Registration failed" });
      } finally {
        await client.end();
      }
    }

    if (method === "POST" && path === "/api/auth/login") {
      const body = event.body ? JSON.parse(event.body) : {};
      const { email, password } = body || {};
      if (!email || !password) return json(400, { detail: "Missing fields" });
      await ensureSchema();
      const client = await getClient();
      try {
        const { rows } = await client.query(
          `select id, email, name, password_hash, age_verified, is_admin, is_approved from users where email=$1`,
          [email]
        );
        if (!rows[0]) return json(400, { detail: "Invalid credentials" });
        const ok = await bcrypt.compare(password, rows[0].password_hash);
        if (!ok) return json(400, { detail: "Invalid credentials" });
        const { password_hash, ...user } = rows[0];
        const token = signToken({ sub: user.id });
        return json(200, { access_token: token, token_type: "bearer", user });
      } finally {
        await client.end();
      }
    }

    if (method === "GET" && path === "/api/auth/profile") {
      const auth = event.headers?.authorization || event.headers?.Authorization || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : undefined;
      if (!token) return json(401, { detail: "Invalid token" });
      try {
        const payload = jwt.verify(token, JWT_SECRET) as any;
        const userId = payload.sub;
        const client = await getClient();
        try {
          const { rows } = await client.query(
            `select id, email, name, age_verified, is_admin, is_approved from users where id=$1`,
            [userId]
          );
          if (!rows[0]) return json(401, { detail: "User not found" });
          return json(200, rows[0]);
        } finally {
          await client.end();
        }
      } catch {
        return json(401, { detail: "Invalid token" });
      }
    }

    // =================== Videos & Storage (Supabase) ===================

    // Add Cloudflare R2 helpers after Supabase client
    async function getS3() {
      const { S3Client } = await import("@aws-sdk/client-s3");
      return new S3Client({
        region: "auto",
        endpoint: R2_ENDPOINT,
        forcePathStyle: true,
            credentials: {
          accessKeyId: R2_ACCESS_KEY_ID,
          secretAccessKey: R2_SECRET_ACCESS_KEY,
        },
      } as any);
    }

    function useR2() {
      console.log("DEBUG: STORAGE_BACKEND =", STORAGE_BACKEND);
      console.log("DEBUG: R2 credentials present =", !!(R2_ENDPOINT && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY));
      if (STORAGE_BACKEND === "supabase") return false;
      if (STORAGE_BACKEND === "local") return false;
      if (STORAGE_BACKEND === "r2") return !!(R2_ENDPOINT && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY);
      // auto: prefer R2 when configured
      return !!(R2_ENDPOINT && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY);
    }

    function useSupabase() {
      if (STORAGE_BACKEND === "r2") return false;
      if (STORAGE_BACKEND === "local") return false;
      if (STORAGE_BACKEND === "supabase") return !!(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY);
      // auto: fallback to supabase if R2 not configured
      return !!(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY);
    }

    function useLocalStorage() {
      if (STORAGE_BACKEND === "local") return true;
      // auto: fallback to local if neither R2 nor Supabase are configured
      return !useR2() && !useSupabase();
    }

    // Upload video (admin only, multipart form-data)
    if (method === "POST" && path === "/api/videos/upload") {
      await ensureSchema();
      try {
        const { userId } = await requireAdmin(event);
        const { fields, file } = await parseMultipart(event);
        if (!file) return json(400, { detail: "No file provided" });
        const title = fields.title?.trim();
        const description = fields.description?.trim();
        const category = fields.category?.trim();
        const tags = (fields.tags || "")
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean);
        if (!title || !description || !category) return json(400, { detail: "Missing fields" });

        // Upload to storage and get storageKey
        const safeName = sanitizeFilename(file.filename || "upload.mp4");
        const storageKey = `${userId}/${randomUUID()}_${safeName}`;
        
        if (useR2()) {
          try {
            const s3 = await getS3();
            // Use AWS SDK directly for server-side upload (no CORS issues)
            const { PutObjectCommand } = await import("@aws-sdk/client-s3");
            const cmd = new PutObjectCommand({
              Bucket: R2_BUCKET,
              Key: storageKey,
              ContentType: file.mimetype || "application/octet-stream",
              Body: file.data,
              Metadata: {
                'uploaded-via': 'server-side',
                'original-filename': file.filename || 'unknown'
              }
            });
            
            console.log("Uploading to R2 via server-side SDK:", storageKey);
            const result = await s3.send(cmd);
            console.log("R2 upload successful:", result.ETag);
          } catch (err: any) {
            console.error("R2 server-side upload error:", err?.message || err);
            if (useSupabase()) {
              const sb = getSupabase();
              const { error: upErr } = await sb.storage.from(SUPABASE_BUCKET).upload(storageKey, file.data, {
                contentType: file.mimetype || "application/octet-stream",
                upsert: false,
              });
              if (upErr) return json(500, { detail: "Upload failed", error: upErr.message });
            } else {
              // Local file storage fallback
              console.log("Using local file storage for:", storageKey);
              try {
                // Go up one level from frontend directory to project root
                const projectRoot = join(process.cwd(), "..");
                const uploadsDir = join(projectRoot, "uploads");
                const userDir = join(uploadsDir, String(userId));
                
                // Create directories if they don't exist
                if (!existsSync(uploadsDir)) mkdirSync(uploadsDir, { recursive: true });
                if (!existsSync(userDir)) mkdirSync(userDir, { recursive: true });
                
                const filePath = join(userDir, `${randomUUID()}_${safeName}`);
                writeFileSync(filePath, file.data);
                console.log("File saved locally to:", filePath);
              } catch (err: any) {
                console.error("Local storage error:", err?.message || err);
                return json(500, { detail: "Local storage failed", error: err?.message || "Unknown error" });
              }
            }
          }
        } else if (useSupabase()) {
          const sb = getSupabase();
          const { error: upErr } = await sb.storage.from(SUPABASE_BUCKET).upload(storageKey, file.data, {
            contentType: file.mimetype || "application/octet-stream",
            upsert: false,
          });
          if (upErr) return json(500, { detail: "Upload failed", error: upErr.message });
        } else {
          // Local file storage fallback
          console.log("Using local file storage for:", storageKey);
          try {
            // Go up one level from frontend directory to project root
            const projectRoot = join(process.cwd(), "..");
            const uploadsDir = join(projectRoot, "uploads");
            const userDir = join(uploadsDir, String(userId));
            
            // Create directories if they don't exist
            if (!existsSync(uploadsDir)) mkdirSync(uploadsDir, { recursive: true });
            if (!existsSync(userDir)) mkdirSync(userDir, { recursive: true });
            
            const filePath = join(userDir, `${randomUUID()}_${safeName}`);
            writeFileSync(filePath, file.data);
            console.log("File saved locally to:", filePath);
          } catch (err: any) {
            console.error("Local storage error:", err?.message || err);
            return json(500, { detail: "Local storage failed", error: err?.message || "Unknown error" });
          }
        }

        const client = await getClient();
        try {
          const { rows } = await client.query(
            `insert into videos (title, description, category, tags, status, uploader_id, storage_key)
             values ($1,$2,$3,$4,$5,$6,$7)
             returning id, title, description, category, tags, status, views`,
            [title, description, category, tags, "pending", userId, storageKey]
          );
          return json(200, rows[0]);
        } finally {
          await client.end();
        }
      } catch (e: any) {
        console.error("Upload endpoint error:", {
          message: e?.message,
          stack: e?.stack,
          name: e?.name
        });
        const msg = e?.message === "Unauthorized" ? 401 : e?.message === "Forbidden" ? 403 : 500;
        return json(msg as number, { 
          detail: e?.message || "Upload error",
          error: e?.stack || e?.toString(),
          timestamp: new Date().toISOString()
        });
      }
    }

    // Create video record after direct-to-R2 upload (admin only)
    if (method === "POST" && path === "/api/videos") {
      await ensureSchema();
      try {
        const { userId } = await requireAdmin(event);
        const body = event.body ? JSON.parse(event.body) : {};
        const title = (body.title || "").toString().trim();
        const description = (body.description || "").toString().trim();
        const category = (body.category || "").toString().trim();
        const storageKey = (body.storageKey || "").toString().trim();
        let tags: string[] = Array.isArray(body.tags)
          ? (body.tags as string[]).map((t) => String(t).trim()).filter(Boolean)
          : String(body.tags || "")
              .split(",")
              .map((t: string) => t.trim())
              .filter(Boolean);
        if (!title || !description || !category || !storageKey) {
          return json(400, { detail: "Missing fields" });
        }

        const client = await getClient();
        try {
          const { rows } = await client.query(
            `insert into videos (title, description, category, tags, status, uploader_id, storage_key)
             values ($1,$2,$3,$4,$5,$6,$7)
             returning id, title, description, category, tags, status, views`,
            [title, description, category, tags, "pending", userId, storageKey]
          );
          return json(200, rows[0]);
        } finally {
          await client.end();
        }
      } catch (e: any) {
        const code = e?.message === "Unauthorized" ? 401 : e?.message === "Forbidden" ? 403 : 500;
        return json(code, { detail: e?.message || "Failed to create record" });
      }
    }

    // List videos (admin can filter by status; non-admins see only approved)
    if (method === "GET" && path === "/api/videos") {
      await ensureSchema();
      let isAdmin = false;
      try {
        const auth = await requireAuth(event);
        isAdmin = !!auth.is_admin;
      } catch {}
      const qs = event.queryStringParameters || {};
      const status = qs.status && typeof qs.status === "string" ? qs.status : undefined;
      const category = qs.category && typeof qs.category === "string" ? qs.category : undefined;

      const where: string[] = [];
      const params: any[] = [];
      if (!isAdmin) {
        where.push("status='approved'");
      } else if (status && status !== "all") {
        params.push(status);
        where.push(`status=$${params.length}`);
      }
      if (category) {
        params.push(category);
        where.push(`category=$${params.length}`);
      }
      const whereSql = where.length ? `where ${where.join(" and ")}` : "";
      const client = await getClient();
      try {
        const { rows } = await client.query(
          `select id, title, description, category, tags, status, views from videos ${whereSql} order by created_at desc`,
          params
        );
        return json(200, rows);
      } finally {
        await client.end();
      }
    }

    // Approve / Reject (admin only)
    {
      const m = path.match(/^\/api\/videos\/(\d+)\/(approve|reject)$/);
      if (method === "POST" && m) {
        await ensureSchema();
        try {
          await requireAdmin(event);
        } catch (e: any) {
          const code = e?.message === "Unauthorized" ? 401 : 403;
          return json(code, { detail: e?.message });
        }
        const id = Number(m[1]);
        const action = m[2];
        const newStatus = action === "approve" ? "approved" : "rejected";
        const client = await getClient();
        try {
          await client.query(`update videos set status=$1, updated_at=now() where id=$2`, [newStatus, id]);
          return json(200, { ok: true });
        } finally {
          await client.end();
        }
      }
    }

    // Delete video (admin only)
    if (method === "DELETE") {
      const m = path.match(/^\/api\/videos\/(\d+)$/);
      if (m) {
        await ensureSchema();
        try {
          await requireAdmin(event);
        } catch (e: any) {
          const code = e?.message === "Unauthorized" ? 401 : 403;
          return json(code, { detail: e?.message });
        }
        const id = Number(m[1]);
        const client = await getClient();
        try {
          const { rows } = await client.query(`select storage_key from videos where id=$1`, [id]);
          const storageKey = rows?.[0]?.storage_key as string | undefined;
          if (storageKey) {
            if (useR2()) {
              const s3 = await getS3();
              // Use presigned URL + fetch for delete to avoid AWS SDK handshake issues
              const { DeleteObjectCommand } = await import("@aws-sdk/client-s3");
              const { getSignedUrl } = await import("@aws-sdk/s3-request-presigner");
              const delCmd = new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: storageKey });
              const delUrl = await getSignedUrl(s3, delCmd, { expiresIn: 60 * 5 });
              const delRes = await fetch(delUrl, { method: "DELETE", headers: { "x-amz-content-sha256": "UNSIGNED-PAYLOAD" } } as any);
              if (!delRes.ok) {
                const text = await (async () => { try { return await delRes.text(); } catch { return ""; } })();
                return json(500, { detail: "Delete failed", error: `R2 DELETE ${delRes.status} ${text}` });
              }
            } else {
              const sb = getSupabase();
              await sb.storage.from(SUPABASE_BUCKET).remove([storageKey]);
            }
          }
          await client.query(`delete from videos where id=$1`, [id]);
          return json(200, { ok: true });
        } finally {
          await client.end();
        }
      }
    }

    // Debug endpoint to check storage_key
    if (method === "GET") {
      const m = path.match(/^\/api\/videos\/(\d+)\/debug$/);
      if (m) {
        const id = Number(m[1]);
        const client = await getClient();
        try {
          const { rows } = await client.query(`select id, title, storage_key, uploader_id from videos where id=$1`, [id]);
          return json(200, { video: rows?.[0] || null });
        } finally {
          await client.end();
        }
      }
    }

    // Temporary endpoint to update storage_key for testing
    if (method === "POST") {
      const m = path.match(/^\/api\/videos\/(\d+)\/update-storage-key$/);
      if (m) {
        const id = Number(m[1]);
        const body = JSON.parse(event.body || '{}');
        const { storage_key } = body;
        
        if (!storage_key) {
          return json(400, { detail: "storage_key is required" });
        }
        
        const client = await getClient();
        try {
          await client.query(`update videos set storage_key=$1 where id=$2`, [storage_key, id]);
          return json(200, { ok: true, message: `Updated video ${id} storage_key to ${storage_key}` });
        } finally {
          await client.end();
        }
      }
    }

    // Stream video (public for approved; admin-only for non-approved)
    if (method === "GET" || method === "HEAD") {
      const m = path.match(/^\/api\/videos\/(\d+)\/stream$/);
      if (m) {
        console.log(`DEBUG: Streaming request for video ${m[1]}`);
        await ensureSchema();
        // Make auth optional for streaming; only required to access non-approved videos
        let authInfo: { userId: number; is_admin: boolean } | null = null;
        try {
          authInfo = await requireAuth(event);
          console.log(`DEBUG: Auth successful for user ${authInfo.userId}, admin: ${authInfo.is_admin}`);
        } catch (e) {
          console.log(`DEBUG: Proceeding without auth for public stream`);
        }
        const id = Number(m[1]);
        const client = await getClient();
        try {
          const { rows } = await client.query(`select status, storage_key from videos where id=$1`, [id]);
          const v = rows?.[0];
          console.log(`DEBUG: Video query result:`, v);
          if (!v) {
            console.log(`DEBUG: Video ${id} not found in database`);
            return json(404, { detail: "Not found" });
          }
          if (v.status !== "approved" && !authInfo?.is_admin) {
            console.log(`DEBUG: Video ${id} not approved and user not admin. Status: ${v.status}, Admin: ${authInfo?.is_admin}`);
            return json(403, { detail: "Forbidden" });
          }
          let redirectUrl: string | null = null;
          if (useR2()) {
            const s3 = await getS3();
            const { GetObjectCommand } = await import("@aws-sdk/client-s3");
            const { getSignedUrl } = await import("@aws-sdk/s3-request-presigner");
            const cmd = new GetObjectCommand({ Bucket: R2_BUCKET, Key: v.storage_key });
            redirectUrl = await getSignedUrl(s3, cmd, { expiresIn: 60 * 60 });
          } else if (useSupabase()) {
            const sb = getSupabase();
            // Instead of redirecting, proxy the file directly to avoid cross-origin/media issues
            if (method === 'HEAD') {
              const { data, error } = await sb.storage.from(SUPABASE_BUCKET).createSignedUrl(v.storage_key, 60 * 60);
              if (error || !data?.signedUrl) return json(404, { detail: 'Video not found' });
              return {
                statusCode: 200,
                headers: {
                  'Accept-Ranges': 'bytes',
                  'Cache-Control': 'public, max-age=60'
                },
                body: ''
              } as any;
            }
            const dl = await sb.storage.from(SUPABASE_BUCKET).download(v.storage_key);
            if (dl.error || !dl.data) return json(500, { detail: 'Failed to download from storage', error: dl.error?.message });
            const buf = Buffer.from(await dl.data.arrayBuffer());
            const total = buf.length;
            const rangeHeader = event.headers?.range || event.headers?.Range;
            const mimeType = v.storage_key.endsWith('.mp4') ? 'video/mp4' : 
                             v.storage_key.endsWith('.mov') ? 'video/quicktime' : 
                             v.storage_key.endsWith('.avi') ? 'video/x-msvideo' : 
                             'video/mp4';
            // Handle HTTP Range requests for streaming
            if (rangeHeader && /^bytes=\d*-\d*$/.test(String(rangeHeader))) {
              const m = String(rangeHeader).match(/bytes=(\d*)-(\d*)/);
              let start = m && m[1] ? parseInt(m[1], 10) : 0;
              let end = m && m[2] ? parseInt(m[2], 10) : total - 1;
              if (isNaN(start) || start < 0) start = 0;
              if (isNaN(end) || end >= total) end = total - 1;
              if (end < start) end = Math.min(start + 1024 * 1024, total - 1); // ensure sane range
              const chunk = buf.subarray(start, end + 1);
              return {
                statusCode: 206,
                headers: {
                  'Content-Type': mimeType,
                  'Content-Length': String(chunk.length),
                  'Content-Range': `bytes ${start}-${end}/${total}`,
                  'Accept-Ranges': 'bytes',
                  'Cache-Control': 'public, max-age=60'
                },
                body: chunk.toString('base64'),
                isBase64Encoded: true
              } as any;
            }
            // No Range header: return full content
            return {
              statusCode: 200,
              headers: {
                'Content-Type': mimeType,
                'Content-Length': String(total),
                'Accept-Ranges': 'bytes',
                'Cache-Control': 'public, max-age=3600'
              },
              body: buf.toString('base64'),
              isBase64Encoded: true
            } as any;
          } else {
            // Local storage: serve file directly
            const { readFileSync, existsSync } = await import("fs");
            // Go up one level from frontend directory to project root
            const projectRoot = join(process.cwd(), "..");
            const uploadsDir = join(projectRoot, "uploads");
            
            // Try new format first (with user subdirectory)
            let filePath = join(uploadsDir, v.storage_key);
            
            // If file doesn't exist, try old format (direct in uploads)
            if (!existsSync(filePath)) {
              // Extract just the filename from storage_key (remove user directory part)
              const filename = v.storage_key.includes('/') ? v.storage_key.split('/').pop() : v.storage_key;
              filePath = join(uploadsDir, filename);
              console.log(`Trying old format path: ${filePath}`);
            }
            
            try {
              const fileData = readFileSync(filePath);
              const mimeType = v.storage_key.endsWith('.mp4') ? 'video/mp4' : 
                             v.storage_key.endsWith('.mov') ? 'video/quicktime' : 
                             v.storage_key.endsWith('.avi') ? 'video/x-msvideo' : 
                             'video/mp4';
              
              return {
                statusCode: 200,
                headers: {
                  'Content-Type': mimeType,
                  'Content-Length': String(fileData.length),
                  'Accept-Ranges': 'bytes',
                  'Cache-Control': 'public, max-age=3600'
                },
                body: fileData.toString('base64'),
                isBase64Encoded: true
              } as any;
            } catch (err: any) {
              console.error("Local file read error:", err?.message || err);
              return json(500, { detail: "File not found", error: err?.message || "Unknown error" });
            }
          }
          // For R2, we still redirect to a signed URL to leverage edge delivery
          if (redirectUrl) {
            return {
              statusCode: 302,
              headers: { Location: redirectUrl },
              body: "",
            } as any;
          }
        } finally {
          await client.end();
        }
      }
    }

    // Categories
    if (method === "GET" && path === "/api/categories") {
      await ensureSchema();
      const client = await getClient();
      try {
        const { rows } = await client.query(`select distinct category from videos where status='approved' order by category asc`);
        const categories = rows.map((r: any) => r.category);
        return json(200, { categories });
      } finally {
        await client.end();
      }
    }

    // Search
    if (method === "POST" && path === "/api/search") {
      await ensureSchema();
      const body = event.body ? JSON.parse(event.body) : {};
      const query = (body.query || "").toString();
      const category = body.category ? body.category.toString() : undefined;
      const params: any[] = [];
      let where = "where status='approved'";
      if (query) {
        params.push(`%${query}%`);
        where += ` and (title ilike $${params.length} or description ilike $${params.length})`;
      }
      if (category) {
        params.push(category);
        where += ` and category=$${params.length}`;
      }
      const client = await getClient();
      try {
        const { rows } = await client.query(
          `select id, title, description, category, tags, status, views from videos ${where} order by created_at desc`,
          params
        );
        return json(200, rows);
      } finally {
        await client.end();
      }
    }

    // =================== Admin: Users ===================

    if (method === "GET" && path === "/api/admin/users") {
      await ensureSchema();
      try {
        await requireAdmin(event);
      } catch (e: any) {
        const code = e?.message === "Unauthorized" ? 401 : 403;
        return json(code, { detail: e?.message });
      }
      const client = await getClient();
      try {
        const { rows } = await client.query(
          `select id, email, name, is_admin, is_approved from users order by created_at desc`
        );
        return json(200, rows);
      } finally {
        await client.end();
      }
    }

    {
      const m = path.match(/^\/api\/admin\/users\/(\d+)\/(approve|make-admin)$/);
      if (method === "POST" && m) {
        await ensureSchema();
        try {
          await requireAdmin(event);
        } catch (e: any) {
          const code = e?.message === "Unauthorized" ? 401 : 403;
          return json(code, { detail: e?.message });
        }
        const id = Number(m[1]);
        const action = m[2];
        const client = await getClient();
        try {
          if (action === "approve") {
            await client.query(`update users set is_approved=true where id=$1`, [id]);
          } else {
            await client.query(`update users set is_admin=true where id=$1`, [id]);
          }
          return json(200, { ok: true });
        } finally {
          await client.end();
        }
      }
    }

    // Dev-only: promote current user to admin (requires JWT, gated by DEV_ALLOW_ELEVATION)
    if (method === "POST" && path === "/api/dev/make-admin") {
      if (!DEV_ALLOW_ELEVATION) {
        return json(404, { detail: "Not found" });
      }
      await ensureSchema();
      try {
        const { userId } = await requireAuth(event);
        const client = await getClient();
        try {
          await client.query(`update users set is_admin=true, is_approved=true where id=$1`, [userId]);
          return json(200, { ok: true });
        } finally {
          await client.end();
        }
      } catch (e: any) {
        const code = e?.message === "Unauthorized" ? 401 : 500;
        return json(code, { detail: e?.message || "Failed to elevate" });
      }
    }

    // Production admin elevation: promote user by email (no auth required, for initial setup)
    if (method === "POST" && path === "/api/admin/bootstrap") {
      await ensureSchema();
      try {
        const body = event.body ? JSON.parse(event.body) : {};
        const { email, secret } = body;
        
        // Simple secret check - you can set ADMIN_BOOTSTRAP_SECRET in Netlify env vars
        const expectedSecret = process.env.ADMIN_BOOTSTRAP_SECRET;
        if (!expectedSecret || secret !== expectedSecret) {
          return json(403, { detail: "Invalid secret" });
        }
        
        if (!email) {
          return json(400, { detail: "Email required" });
        }
        
        const client = await getClient();
        try {
          const { rows } = await client.query(
            `update users set is_admin=true, is_approved=true where email=$1 returning id, email, is_admin`,
            [email]
          );
          if (rows.length === 0) {
            return json(404, { detail: "User not found" });
          }
          return json(200, { user: rows[0], message: "User elevated to admin" });
        } finally {
          await client.end();
        }
      } catch (e: any) {
        return json(500, { detail: e?.message || "Bootstrap failed" });
      }
    }
    // Dev-only: create video DB record using storageKey (bypass server-side upload)
    if (method === "POST" && path === "/api/dev/videos/create") {
      if (!DEV_ALLOW_ELEVATION) {
        return json(404, { detail: "Not found" });
      }
      await ensureSchema();
      try {
        const { userId } = await requireAdmin(event);
        const { fields } = await parseMultipart(event);
        const title = fields.title?.trim();
        const description = fields.description?.trim();
        const category = fields.category?.trim();
        const storageKey = fields.storageKey?.trim();
        const tags = (fields.tags || "")
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean);
        if (!title || !description || !category || !storageKey) {
          return json(400, { detail: "Missing fields" });
        }
        const client = await getClient();
        try {
          const { rows } = await client.query(
            `insert into videos (title, description, category, tags, status, uploader_id, storage_key)
             values ($1,$2,$3,$4,$5,$6,$7)
             returning id, title, description, category, tags, status, views`,
            [title, description, category, tags, "pending", userId, storageKey]
          );
          return json(200, rows[0]);
        } finally {
          await client.end();
        }
      } catch (e: any) {
        const code = e?.message === "Unauthorized" ? 401 : 500;
        return json(code, { detail: e?.message || "Failed to create record" });
      }
    }

    // Dev-only: delete video DB record by id (skip storage deletion)
    if (method === "POST" && path === "/api/dev/videos/delete-db") {
      if (!DEV_ALLOW_ELEVATION) {
        return json(404, { detail: "Not found" });
      }
      await ensureSchema();
      try {
        await requireAdmin(event);
        const { fields } = await parseMultipart(event);
        const id = Number(fields.id);
        if (!id) return json(400, { detail: "Missing id" });
        const client = await getClient();
        try {
          await client.query(`delete from videos where id=$1`, [id]);
          return json(200, { ok: true });
        } finally {
          await client.end();
        }
      } catch (e: any) {
        const code = e?.message === "Unauthorized" ? 401 : 500;
        return json(code, { detail: e?.message || "Failed to delete record" });
      }
    }

    // Dev-only: migrate local uploads to Supabase and normalize storage_key
    if (method === "POST" && path === "/api/dev/migrate-supabase") {
      if (!DEV_ALLOW_ELEVATION) {
        return json(404, { detail: "Not found" });
      }
      await ensureSchema();

      // Ensure Supabase is configured
      if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
        return json(400, { detail: "Supabase env missing" });
      }

      // Helper to guess content type
      function guessContentType(name: string) {
        const lower = name.toLowerCase();
        if (lower.endsWith('.mp4')) return 'video/mp4';
        if (lower.endsWith('.mov')) return 'video/quicktime';
        if (lower.endsWith('.avi')) return 'video/x-msvideo';
        if (lower.endsWith('.mkv')) return 'video/x-matroska';
        return 'application/octet-stream';
      }

      const client = await getClient();
      try {
        const { rows } = await client.query(`select id, storage_key, uploader_id from videos order by id asc`);
        // Resolve uploads directory robustly across environments
        const possibleUploads = [
          join(process.cwd(), "uploads"),
          join(process.cwd(), "..", "uploads"),
          join(process.cwd(), "..", "..", "uploads"),
        ];
        const uploadsDir = possibleUploads.find((p) => existsSync(p)) || join(process.cwd(), "..", "uploads");
        let total = 0, uploaded = 0, skipped = 0, updatedKeys = 0, missing = 0, failed = 0;
        const sb = getSupabase();

        for (const v of rows) {
          total++;
          const id = v.id as number;
          const storage_key = v.storage_key as string;
          const uploader_id = v.uploader_id as number;

          // Determine local file path (support new and legacy formats)
          let candidatePaths: string[] = [];
          candidatePaths.push(join(uploadsDir, storage_key));
          const base = storage_key.includes('/') ? storage_key.split('/').pop()! : storage_key;
          candidatePaths.push(join(uploadsDir, base));
          candidatePaths.push(join(uploadsDir, String(uploader_id), base));

          let localPath = candidatePaths.find(p => existsSync(p));
          if (!localPath) {
            // Fallback: try matching by UUID-only filename patterns
            // Try matching any UUID present in the storage_key string
            const uuidRegex = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ig;
            const allUuids = storage_key.match(uuidRegex) || [];
            const exts = ['.mp4', '.MP4', '.mov', '.MOV', '.avi', '.AVI', '.mkv', '.MKV'];
            for (const uuid of allUuids) {
              for (const ext of exts) {
                const byUuid = join(uploadsDir, `${uuid}${ext}`);
                if (existsSync(byUuid)) {
                  localPath = byUuid;
                  break;
                }
              }
              if (localPath) break;
            }
            if (!localPath) {
              console.warn(`[${id}] Missing local file for storage_key=${storage_key}`);
              missing++;
              continue;
            }
          }

          // Decide Supabase object key
          const newKey = storage_key.includes('/') ? storage_key : `${uploader_id}/${storage_key}`;
          const needsUpdate = newKey !== storage_key;

          try {
            const data = readFileSync(localPath);
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
              await client.query('update videos set storage_key=$1, updated_at=now() where id=$2', [newKey, id]);
              updatedKeys++;
            }
          } catch (e: any) {
            console.error(`[${id}] Migration error:`, e?.message || e);
            failed++;
          }
        }

        return json(200, { total, uploaded, missing, failed, updatedKeys });
      } finally {
        await client.end();
      }
    }

    return json(404, { detail: "Not found" });
  } catch (err: any) {
    return json(500, { detail: "Server error", error: err?.message });
  }
};