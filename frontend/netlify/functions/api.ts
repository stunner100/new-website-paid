import { Handler } from "@netlify/functions";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Client } from "pg";
// NEW: storage and upload utils
import Busboy from "busboy";
import { createClient } from "@supabase/supabase-js";
import { randomUUID } from "crypto";

const DATABASE_URL = process.env.DATABASE_URL as string;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
// NEW: Supabase envs
const SUPABASE_URL = process.env.SUPABASE_URL as string;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY as string;
const SUPABASE_BUCKET = process.env.SUPABASE_BUCKET || "videos";

function json(statusCode: number, body: any, headers: Record<string, string> = {}) {
  return {
    statusCode,
    headers: { "content-type": "application/json", ...headers },
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
        const ok = await bcrypt.compare(rows[0].password_hash ? password : "", rows[0].password_hash);
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

        const sb = getSupabase();
        const safeName = sanitizeFilename(file.filename || "upload.mp4");
        const storageKey = `${userId}/${randomUUID()}_${safeName}`;
        const { error: upErr } = await sb.storage.from(SUPABASE_BUCKET).upload(storageKey, file.data, {
          contentType: file.mimetype || "application/octet-stream",
          upsert: false,
        });
        if (upErr) return json(500, { detail: "Upload failed", error: upErr.message });

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
        const msg = e?.message === "Unauthorized" ? 401 : e?.message === "Forbidden" ? 403 : 500;
        return json(msg as number, { detail: e?.message || "Upload error" });
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
            const sb = getSupabase();
            await sb.storage.from(SUPABASE_BUCKET).remove([storageKey]);
          }
          await client.query(`delete from videos where id=$1`, [id]);
          return json(200, { ok: true });
        } finally {
          await client.end();
        }
      }
    }

    // Stream video (requires auth; approved or admin)
    if (method === "GET") {
      const m = path.match(/^\/api\/videos\/(\d+)\/stream$/);
      if (m) {
        await ensureSchema();
        let authInfo: { userId: number; is_admin: boolean } | null = null;
        try {
          authInfo = await requireAuth(event);
        } catch {
          return json(401, { detail: "Invalid token" });
        }
        const id = Number(m[1]);
        const client = await getClient();
        try {
          const { rows } = await client.query(`select status, storage_key from videos where id=$1`, [id]);
          const v = rows?.[0];
          if (!v) return json(404, { detail: "Not found" });
          if (v.status !== "approved" && !authInfo?.is_admin) return json(403, { detail: "Forbidden" });
          const sb = getSupabase();
          const { data, error } = await sb.storage.from(SUPABASE_BUCKET).createSignedUrl(v.storage_key, 60 * 60);
          if (error || !data?.signedUrl) return json(500, { detail: "Failed to sign URL", error: error?.message });
          return {
            statusCode: 302,
            headers: { Location: data.signedUrl },
            body: "",
          } as any;
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

    return json(404, { detail: "Not found" });
  } catch (err: any) {
    return json(500, { detail: "Server error", error: err?.message });
  }
};