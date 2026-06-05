const LATEST_VERSION = "20260605-3";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 14;
const PBKDF2_ITERATIONS = 100000;
const CLOUD_DISABLED_USERS = new Set(["guest"]);

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" }
  });
}

function emptyAccount(username) {
  return {
    username,
    site: { version: LATEST_VERSION, visitedCases: {}, updatedAt: null },
    cases: {},
    updatedAt: null
  };
}

function safeJsonParse(value, fallback) {
  if (!value) return fallback;
  try { return JSON.parse(value); } catch (error) { return fallback; }
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function randomToken(bytes = 32) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return bytesToBase64(data).replace(/[+/=]/g, "");
}

async function hashPassword(password, saltBase64 = null) {
  const salt = saltBase64 ? base64ToBytes(saltBase64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(String(password || "")), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, key, 256);
  return { salt: bytesToBase64(salt), hash: bytesToBase64(new Uint8Array(bits)), iterations: PBKDF2_ITERATIONS };
}

async function verifyPassword(password, record) {
  if (!record?.password?.salt || !record?.password?.hash) return false;
  const result = await hashPassword(password, record.password.salt);
  return result.hash === record.password.hash;
}

function rowToUser(row) {
  if (!row) return null;
  return {
    username: row.username,
    role: row.role || "investigator",
    password: safeJsonParse(row.password_json, null),
    createdAt: row.created_at || null,
    updatedAt: row.updated_at || null
  };
}

function publicUser(record) {
  if (!record) return null;
  return {
    username: record.username,
    role: record.role || "investigator",
    createdAt: record.createdAt || null,
    updatedAt: record.updatedAt || null
  };
}

async function initDatabase(env) {
  await env.TTJ_SAVES.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      role TEXT NOT NULL,
      password_json TEXT NOT NULL,
      created_at TEXT,
      updated_at TEXT
    )
  `).run();
  await env.TTJ_SAVES.prepare(`
    CREATE TABLE IF NOT EXISTS accounts (
      username TEXT PRIMARY KEY,
      site_json TEXT,
      cases_json TEXT,
      updated_at TEXT
    )
  `).run();
  await env.TTJ_SAVES.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at TEXT,
      expires_at INTEGER
    )
  `).run();
  await env.TTJ_SAVES.prepare(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `).run();
  await env.TTJ_SAVES.prepare(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at TEXT NOT NULL,
      actor_username TEXT,
      target_username TEXT,
      action TEXT NOT NULL,
      case_id TEXT,
      ip TEXT,
      user_agent TEXT,
      country TEXT,
      city TEXT,
      detail_json TEXT
    )
  `).run();
  await env.TTJ_SAVES.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(Date.now()).run();
}

async function getSetting(env, key) {
  const row = await env.TTJ_SAVES.prepare("SELECT value FROM settings WHERE key = ?").bind(key).first();
  return row?.value || null;
}

async function setSetting(env, key, value) {
  await env.TTJ_SAVES.prepare(`
    INSERT INTO settings (key, value)
    VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).bind(key, value).run();
}

async function readUser(env, username) {
  const row = await env.TTJ_SAVES.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
  return rowToUser(row);
}

async function createUserRecord(env, username, password, role = "investigator") {
  const now = new Date().toISOString();
  const passwordRecord = await hashPassword(password);
  await env.TTJ_SAVES.prepare(`
    INSERT INTO users (username, role, password_json, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?)
  `).bind(username, role, JSON.stringify(passwordRecord), now, now).run();
  await ensureAccount(env, username);
  return publicUser({ username, role, password: passwordRecord, createdAt: now, updatedAt: now });
}

async function ensureBootstrapUsers(env) {
  if (await getSetting(env, "bootstrapped")) return;
  const seeds = [
    ["guest", env.GUEST_PASSWORD, "investigator", "GUEST_PASSWORD"],
    ["winne", env.WINNE_PASSWORD, "investigator", "WINNE_PASSWORD"],
    ["admin", env.ADMIN_PASSWORD, "administrator", "ADMIN_PASSWORD"]
  ];
  const missing = seeds.filter(([, password]) => !password).map(([, , , name]) => name);
  if (missing.length) throw new Error(`Missing initial password variables: ${missing.join(", ")}`);
  for (const [username, password, role] of seeds) {
    if (!(await readUser(env, username))) await createUserRecord(env, username, password, role);
  }
  await setSetting(env, "bootstrapped", new Date().toISOString());
}

async function ensureAccount(env, username) {
  const existing = await env.TTJ_SAVES.prepare("SELECT username FROM accounts WHERE username = ?").bind(username).first();
  if (existing) return;
  const account = emptyAccount(username);
  await env.TTJ_SAVES.prepare(`
    INSERT INTO accounts (username, site_json, cases_json, updated_at)
    VALUES (?, ?, ?, ?)
  `).bind(username, JSON.stringify(account.site), JSON.stringify(account.cases), account.updatedAt).run();
}

async function readAccount(env, username) {
  const row = await env.TTJ_SAVES.prepare("SELECT * FROM accounts WHERE username = ?").bind(username).first();
  if (!row) return emptyAccount(username);
  const account = {
    username: row.username,
    site: safeJsonParse(row.site_json, emptyAccount(username).site),
    cases: safeJsonParse(row.cases_json, {}),
    updatedAt: row.updated_at || null
  };
  account.site = account.site || emptyAccount(username).site;
  account.site.visitedCases = account.site.visitedCases || {};
  account.cases = account.cases || {};
  return account;
}

async function writeAccount(env, username, account) {
  const next = {
    ...emptyAccount(username),
    ...(account || {}),
    username,
    site: account?.site || emptyAccount(username).site,
    cases: account?.cases || {},
    updatedAt: new Date().toISOString()
  };
  await env.TTJ_SAVES.prepare(`
    INSERT INTO accounts (username, site_json, cases_json, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(username) DO UPDATE SET
      site_json = excluded.site_json,
      cases_json = excluded.cases_json,
      updated_at = excluded.updated_at
  `).bind(username, JSON.stringify(next.site), JSON.stringify(next.cases), next.updatedAt).run();
  return next;
}

async function makeSession(env, user) {
  const token = randomToken();
  const createdAt = new Date().toISOString();
  const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
  await env.TTJ_SAVES.prepare(`
    INSERT INTO sessions (token, username, role, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).bind(token, user.username, user.role || "investigator", createdAt, expiresAt).run();
  return { token, username: user.username, role: user.role || "investigator", createdAt, expiresAt };
}

async function requireSession(env, body) {
  const token = String(body.sessionToken || "").trim();
  if (!token) return null;
  const row = await env.TTJ_SAVES.prepare("SELECT * FROM sessions WHERE token = ?").bind(token).first();
  if (!row) return null;
  if (!row.expires_at || Number(row.expires_at) <= Date.now()) {
    await env.TTJ_SAVES.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    return null;
  }
  const user = await readUser(env, row.username);
  if (!user) {
    await env.TTJ_SAVES.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    return null;
  }
  return {
    token,
    username: user.username,
    role: user.role || row.role || "investigator",
    createdAt: row.created_at || null,
    expiresAt: row.expires_at
  };
}

async function requireAdmin(env, body) {
  const session = await requireSession(env, body);
  if (!session || session.role !== "administrator") return null;
  return session;
}

function targetUsername(body, session) {
  return session.role === "administrator" && body.targetUsername ? String(body.targetUsername).trim() : session.username;
}

function isCloudDisabledUser(username) {
  return CLOUD_DISABLED_USERS.has(String(username || "").trim().toLowerCase());
}

async function deleteUserAndData(env, username) {
  await env.TTJ_SAVES.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
  await env.TTJ_SAVES.prepare("DELETE FROM accounts WHERE username = ?").bind(username).run();
  await env.TTJ_SAVES.prepare("DELETE FROM sessions WHERE username = ?").bind(username).run();
}

function requestMeta(request) {
  const cf = request.cf || {};
  return {
    ip: request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "",
    userAgent: request.headers.get("User-Agent") || "",
    country: cf.country || "",
    city: cf.city || ""
  };
}

async function logEvent(env, request, { actorUsername = "", targetUsername = "", action, caseId = "", detail = {} }) {
  const meta = requestMeta(request);
  await env.TTJ_SAVES.prepare(`
    INSERT INTO audit_logs (created_at, actor_username, target_username, action, case_id, ip, user_agent, country, city, detail_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    new Date().toISOString(),
    actorUsername,
    targetUsername,
    action,
    caseId,
    meta.ip,
    meta.userAgent,
    meta.country,
    meta.city,
    JSON.stringify(detail || {})
  ).run();
}

function summarizeCaseProgress(save) {
  if (!save || typeof save !== "object") return { unlockedDocIds: [], unlockedCount: 0, step: "未开始" };
  const unlockedDocIds = Array.isArray(save.documents) ? save.documents.filter(doc => doc?.unlocked).map(doc => doc.id) : [];
  let step = "调查中";
  if (save.isSealed) step = "已封存";
  else if (save.goodEndingAchieved) step = "已完成真相推理";
  else if (unlockedDocIds.length) step = `已解锁 ${unlockedDocIds.length} 份档案`;
  return {
    unlockedDocIds,
    unlockedCount: unlockedDocIds.length,
    step,
    goodEndingAchieved: !!save.goodEndingAchieved,
    isSealed: !!save.isSealed,
    savedAt: save.savedAt || save.cloudSavedAt || null
  };
}

function summarizeAccountProgress(account) {
  const cases = {};
  for (const [caseId, save] of Object.entries(account?.cases || {})) cases[caseId] = summarizeCaseProgress(save);
  return { site: account?.site || {}, cases };
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
    if (request.method !== "POST") return json({ ok: false, latestVersion: LATEST_VERSION, error: "POST only" }, 405);
    if (!env.TTJ_SAVES || typeof env.TTJ_SAVES.prepare !== "function") {
      return json({ ok: false, latestVersion: LATEST_VERSION, error: "D1 binding TTJ_SAVES missing" }, 500);
    }

    try {
      await initDatabase(env);
      await ensureBootstrapUsers(env);
    } catch (error) {
      const message = String(error?.message || "");
      if (message.includes("Missing initial password variables")) {
        return json({ ok: false, latestVersion: LATEST_VERSION, error: "初始账号密码环境变量未设置" }, 500);
      }
      return json({ ok: false, latestVersion: LATEST_VERSION, error: "D1 数据库初始化失败" }, 500);
    }

    let body;
    try {
      body = await request.json();
    } catch (error) {
      return json({ ok: false, latestVersion: LATEST_VERSION, error: "Invalid JSON" }, 400);
    }

    if (body.action === "login") {
      try {
        const username = String(body.username || "").trim();
        const password = String(body.password || "");
        const user = await readUser(env, username);
        if (!user || !(await verifyPassword(password, user))) {
          await logEvent(env, request, { actorUsername: username, targetUsername: username, action: "login_failed", detail: { reason: "bad_credentials" } });
          return json({ ok: false, latestVersion: LATEST_VERSION, error: "账号或密码错误" }, 401);
        }
        await ensureAccount(env, username);
        const session = await makeSession(env, user);
        const account = await readAccount(env, username);
        await logEvent(env, request, { actorUsername: username, targetUsername: username, action: "login_success", detail: { role: user.role } });
        if (isCloudDisabledUser(username)) {
          return json({ ok: true, latestVersion: LATEST_VERSION, user: publicUser(user), sessionToken: session.token, site: emptyAccount(username).site, cases: {}, cloudDisabled: true });
        }
        return json({ ok: true, latestVersion: LATEST_VERSION, user: publicUser(user), sessionToken: session.token, site: account.site, cases: account.cases });
      } catch (error) {
        return json({ ok: false, latestVersion: LATEST_VERSION, error: `登录服务异常: ${String(error?.message || error)}` }, 500);
      }
    }

    if (body.action === "logout") {
      if (body.sessionToken) await env.TTJ_SAVES.prepare("DELETE FROM sessions WHERE token = ?").bind(String(body.sessionToken).trim()).run();
      return json({ ok: true, latestVersion: LATEST_VERSION });
    }

    const session = await requireSession(env, body);
    if (!session) return json({ ok: false, latestVersion: LATEST_VERSION, error: "未登录或会话已过期" }, 401);
    const username = targetUsername(body, session);
    const account = await readAccount(env, username);

    if (body.action === "pull") {
      if (isCloudDisabledUser(username) && session.role !== "administrator") {
        return json({ ok: true, latestVersion: LATEST_VERSION, user: { username: session.username, role: session.role }, account: emptyAccount(username), site: emptyAccount(username).site, cases: {}, cloudDisabled: true });
      }
      return json({ ok: true, latestVersion: LATEST_VERSION, user: { username: session.username, role: session.role }, account, site: account.site, cases: account.cases });
    }

    if (body.action === "pushSite") {
      if (username !== session.username && session.role !== "administrator") return json({ ok: false, latestVersion: LATEST_VERSION, error: "权限不足" }, 403);
      if (!body.site || typeof body.site !== "object") return json({ ok: false, latestVersion: LATEST_VERSION, error: "Missing site save" }, 400);
      if (isCloudDisabledUser(username)) {
        await logEvent(env, request, { actorUsername: session.username, targetUsername: username, action: "push_site_skipped", detail: { reason: "cloud_disabled" } });
        return json({ ok: true, latestVersion: LATEST_VERSION, site: emptyAccount(username).site, cloudDisabled: true });
      }
      account.site = { ...account.site, ...body.site, version: body.site.version || LATEST_VERSION, updatedAt: new Date().toISOString() };
      const next = await writeAccount(env, username, account);
      await logEvent(env, request, { actorUsername: session.username, targetUsername: username, action: "push_site", detail: { visitedCases: Object.keys(next.site?.visitedCases || {}) } });
      return json({ ok: true, latestVersion: LATEST_VERSION, site: next.site });
    }

    if (body.action === "pullCase") {
      const caseId = String(body.caseId || "").trim();
      if (!caseId) return json({ ok: false, latestVersion: LATEST_VERSION, error: "Missing caseId" }, 400);
      if (isCloudDisabledUser(username) && session.role !== "administrator") {
        return json({ ok: true, latestVersion: LATEST_VERSION, save: null, cloudDisabled: true });
      }
      return json({ ok: true, latestVersion: LATEST_VERSION, save: account.cases?.[caseId] || null });
    }

    if (body.action === "pushCase") {
      if (username !== session.username && session.role !== "administrator") return json({ ok: false, latestVersion: LATEST_VERSION, error: "权限不足" }, 403);
      const caseId = String(body.caseId || body.save?.caseId || "").trim();
      if (!caseId) return json({ ok: false, latestVersion: LATEST_VERSION, error: "Missing caseId" }, 400);
      if (!body.save || typeof body.save !== "object") return json({ ok: false, latestVersion: LATEST_VERSION, error: "Missing case save" }, 400);
      if (isCloudDisabledUser(username)) {
        await logEvent(env, request, { actorUsername: session.username, targetUsername: username, action: "push_case_skipped", caseId, detail: { reason: "cloud_disabled", progress: summarizeCaseProgress(body.save) } });
        return json({ ok: true, latestVersion: LATEST_VERSION, save: null, site: emptyAccount(username).site, cloudDisabled: true });
      }
      account.cases = account.cases || {};
      account.cases[caseId] = { ...body.save, caseId, currentUser: body.save.currentUser || { username }, cloudSavedAt: new Date().toISOString() };
      account.site = account.site || emptyAccount(username).site;
      account.site.visitedCases = account.site.visitedCases || {};
      account.site.visitedCases[caseId] = { ...(account.site.visitedCases[caseId] || {}), lastSynced: new Date().toISOString() };
      const next = await writeAccount(env, username, account);
      await logEvent(env, request, { actorUsername: session.username, targetUsername: username, action: "push_case", caseId, detail: summarizeCaseProgress(next.cases[caseId]) });
      return json({ ok: true, latestVersion: LATEST_VERSION, save: next.cases[caseId], site: next.site });
    }

    if (body.action === "deleteCase") {
      if (username !== session.username && session.role !== "administrator") return json({ ok: false, latestVersion: LATEST_VERSION, error: "权限不足" }, 403);
      const caseId = String(body.caseId || "").trim();
      if (!caseId) return json({ ok: false, latestVersion: LATEST_VERSION, error: "Missing caseId" }, 400);
      delete account.cases?.[caseId];
      if (account.site?.visitedCases) delete account.site.visitedCases[caseId];
      await writeAccount(env, username, account);
      await logEvent(env, request, { actorUsername: session.username, targetUsername: username, action: "delete_case", caseId });
      return json({ ok: true, latestVersion: LATEST_VERSION });
    }

    if (body.action === "deleteAccount") {
      const name = targetUsername(body, session);
      if (!name) return json({ ok: false, latestVersion: LATEST_VERSION, error: "账号不能为空" }, 400);
      if (name !== session.username && session.role !== "administrator") return json({ ok: false, latestVersion: LATEST_VERSION, error: "权限不足" }, 403);
      await deleteUserAndData(env, name);
      await logEvent(env, request, { actorUsername: session.username, targetUsername: name, action: "delete_account" });
      return json({ ok: true, latestVersion: LATEST_VERSION });
    }

    const admin = await requireAdmin(env, body);
    if (!admin) return json({ ok: false, latestVersion: LATEST_VERSION, error: "权限不足" }, 403);

    if (body.action === "adminListUsers") {
      const result = await env.TTJ_SAVES.prepare("SELECT username, role, created_at, updated_at FROM users ORDER BY username ASC").all();
      const users = (result.results || []).map(row => publicUser(rowToUser({ ...row, password_json: "{}" })));
      return json({ ok: true, latestVersion: LATEST_VERSION, users });
    }

    if (body.action === "adminCreateUser") {
      const newUsername = String(body.newUsername || "").trim();
      const newPassword = String(body.newPassword || "");
      const role = body.role === "administrator" ? "administrator" : "investigator";
      if (!newUsername || !newPassword) return json({ ok: false, latestVersion: LATEST_VERSION, error: "账号和密码不能为空" }, 400);
      if (await readUser(env, newUsername)) return json({ ok: false, latestVersion: LATEST_VERSION, error: "账号已存在" }, 409);
      const user = await createUserRecord(env, newUsername, newPassword, role);
      await logEvent(env, request, { actorUsername: admin.username, targetUsername: newUsername, action: "admin_create_user", detail: { role } });
      return json({ ok: true, latestVersion: LATEST_VERSION, user });
    }

    if (body.action === "adminDeleteUser") {
      const name = String(body.targetUsername || "").trim();
      if (!name || name === admin.username) return json({ ok: false, latestVersion: LATEST_VERSION, error: "不能删除该账号" }, 400);
      await deleteUserAndData(env, name);
      await logEvent(env, request, { actorUsername: admin.username, targetUsername: name, action: "admin_delete_user" });
      return json({ ok: true, latestVersion: LATEST_VERSION });
    }

    if (body.action === "adminResetPassword") {
      const name = String(body.targetUsername || "").trim();
      const newPassword = String(body.newPassword || "");
      const user = await readUser(env, name);
      if (!user || !newPassword) return json({ ok: false, latestVersion: LATEST_VERSION, error: "账号不存在或密码为空" }, 400);
      const passwordRecord = await hashPassword(newPassword);
      const now = new Date().toISOString();
      await env.TTJ_SAVES.prepare("UPDATE users SET password_json = ?, updated_at = ? WHERE username = ?").bind(JSON.stringify(passwordRecord), now, name).run();
      await env.TTJ_SAVES.prepare("DELETE FROM sessions WHERE username = ?").bind(name).run();
      await logEvent(env, request, { actorUsername: admin.username, targetUsername: name, action: "admin_reset_password" });
      return json({ ok: true, latestVersion: LATEST_VERSION, user: publicUser({ ...user, updatedAt: now }) });
    }

    if (body.action === "adminGetAccount") {
      const name = String(body.targetUsername || "").trim();
      const user = await readUser(env, name);
      if (!user) return json({ ok: false, latestVersion: LATEST_VERSION, error: "账号不存在" }, 404);
      const targetAccount = await readAccount(env, name);
      await logEvent(env, request, { actorUsername: admin.username, targetUsername: name, action: "admin_get_account" });
      return json({ ok: true, latestVersion: LATEST_VERSION, user: publicUser(user), account: targetAccount, progress: summarizeAccountProgress(targetAccount) });
    }

    if (body.action === "adminPutAccount") {
      const name = String(body.targetUsername || "").trim();
      if (!name || !body.account || typeof body.account !== "object") return json({ ok: false, latestVersion: LATEST_VERSION, error: "参数错误" }, 400);
      if (!(await readUser(env, name))) return json({ ok: false, latestVersion: LATEST_VERSION, error: "账号不存在" }, 404);
      await writeAccount(env, name, body.account);
      await logEvent(env, request, { actorUsername: admin.username, targetUsername: name, action: "admin_put_account", detail: summarizeAccountProgress(body.account) });
      return json({ ok: true, latestVersion: LATEST_VERSION, account: await readAccount(env, name) });
    }

    if (body.action === "adminGetUserDetails") {
      const name = String(body.targetUsername || "").trim();
      const user = await readUser(env, name);
      if (!user) return json({ ok: false, latestVersion: LATEST_VERSION, error: "账号不存在" }, 404);
      const targetAccount = await readAccount(env, name);
      const logs = await env.TTJ_SAVES.prepare(`
        SELECT id, created_at, actor_username, target_username, action, case_id, ip, user_agent, country, city, detail_json
        FROM audit_logs
        WHERE actor_username = ? OR target_username = ?
        ORDER BY id DESC
        LIMIT 80
      `).bind(name, name).all();
      await logEvent(env, request, { actorUsername: admin.username, targetUsername: name, action: "admin_get_user_details" });
      return json({
        ok: true,
        latestVersion: LATEST_VERSION,
        user: publicUser(user),
        account: targetAccount,
        progress: summarizeAccountProgress(targetAccount),
        logs: (logs.results || []).map(row => ({ ...row, detail: safeJsonParse(row.detail_json, {}) }))
      });
    }

    if (body.action === "adminListAuditLogs") {
      const target = String(body.targetUsername || "").trim();
      const type = String(body.eventType || "").trim();
      const limit = Math.min(Math.max(Number(body.limit || 100), 1), 300);
      const clauses = [];
      const params = [];
      if (target) { clauses.push("(actor_username = ? OR target_username = ?)"); params.push(target, target); }
      if (type) { clauses.push("action = ?"); params.push(type); }
      params.push(limit);
      const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
      const logs = await env.TTJ_SAVES.prepare(`
        SELECT id, created_at, actor_username, target_username, action, case_id, ip, user_agent, country, city, detail_json
        FROM audit_logs
        ${where}
        ORDER BY id DESC
        LIMIT ?
      `).bind(...params).all();
      return json({
        ok: true,
        latestVersion: LATEST_VERSION,
        logs: (logs.results || []).map(row => ({ ...row, detail: safeJsonParse(row.detail_json, {}) }))
      });
    }

    return json({ ok: false, latestVersion: LATEST_VERSION, error: "Unknown action" }, 400);
  }
};
