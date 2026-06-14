const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

async function supabaseFetch(path, options = {}) {
  const response = await fetch(`${SUPABASE_URL}${path}`, {
    ...options,
    headers: {
      apikey: SERVICE_ROLE_KEY,
      authorization: `Bearer ${SERVICE_ROLE_KEY}`,
      "content-type": "application/json",
      ...(options.headers || {})
    }
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(data?.message || data?.error_description || data?.error || response.statusText);
  }
  return data;
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

async function requireAdmin(req) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  if (!token) throw new Error("Missing login token");

  const user = await supabaseFetch("/auth/v1/user", {
    headers: { authorization: `Bearer ${token}` }
  });
  const profiles = await supabaseFetch(`/rest/v1/profiles?user_id=eq.${user.id}&select=role`);
  if (profiles?.[0]?.role !== "admin") throw new Error("Admin only");
  return user;
}

export default async function handler(req, res) {
  if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
    return send(res, 500, { error: "Server is missing Supabase environment variables." });
  }

  try {
    await requireAdmin(req);
    const body = await readJson(req);

    if (req.method === "POST") {
      const { email, password, display_name } = body;
      if (!email || !password || !display_name) {
        return send(res, 400, { error: "Email, password, and display_name are required." });
      }

      const created = await supabaseFetch("/auth/v1/admin/users", {
        method: "POST",
        body: JSON.stringify({
          email,
          password,
          email_confirm: true,
          user_metadata: { display_name }
        })
      });

      await supabaseFetch("/rest/v1/profiles", {
        method: "POST",
        headers: { prefer: "resolution=merge-duplicates" },
        body: JSON.stringify({
          user_id: created.id,
          email,
          display_name,
          role: "judge"
        })
      });

      return send(res, 200, { user_id: created.id });
    }

    if (req.method === "PATCH") {
      const { user_id, email, password, display_name, role } = body;
      if (!user_id) return send(res, 400, { error: "user_id is required." });

      const authPatch = {};
      if (email) authPatch.email = email;
      if (password) authPatch.password = password;
      if (display_name) authPatch.user_metadata = { display_name };
      if (Object.keys(authPatch).length) {
        await supabaseFetch(`/auth/v1/admin/users/${user_id}`, {
          method: "PATCH",
          body: JSON.stringify(authPatch)
        });
      }

      const profilePatch = {};
      if (email) profilePatch.email = email;
      if (display_name) profilePatch.display_name = display_name;
      if (role) profilePatch.role = role;
      if (Object.keys(profilePatch).length) {
        await supabaseFetch(`/rest/v1/profiles?user_id=eq.${user_id}`, {
          method: "PATCH",
          headers: { prefer: "return=minimal" },
          body: JSON.stringify(profilePatch)
        });
      }

      return send(res, 200, { ok: true });
    }

    if (req.method === "DELETE") {
      const { user_id } = body;
      if (!user_id) return send(res, 400, { error: "user_id is required." });
      await supabaseFetch(`/auth/v1/admin/users/${user_id}`, { method: "DELETE" });
      return send(res, 200, { ok: true });
    }

    return send(res, 405, { error: "Method not allowed." });
  } catch (error) {
    return send(res, 403, { error: error.message || "Request failed." });
  }
}
