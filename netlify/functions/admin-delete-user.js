const res = (s, b) => ({ statusCode: s, headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) });
exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return res(405, { error: "Method not allowed" });
  const U = process.env.SUPABASE_URL, K = process.env.SUPABASE_SERVICE_KEY;
  if (!U || !K) return res(500, { error: "Server belum dikonfigurasi" });
  const token = (event.headers.authorization || "").replace(/^Bearer /i, "");
  let id; try { id = JSON.parse(event.body || "{}").id; } catch (e) {}
  if (!token || !id) return res(400, { error: "Permintaan tidak valid" });
  const me = await fetch(U + "/auth/v1/user", { headers: { apikey: K, Authorization: "Bearer " + token } });
  if (!me.ok) return res(401, { error: "Sesi tidak valid" });
  const caller = (await me.json()).id, h = { apikey: K, Authorization: "Bearer " + K };
  const prof = async (x) => (await (await fetch(U + "/rest/v1/profiles?select=role,is_active&id=eq." + encodeURIComponent(x), { headers: h })).json())[0];
  const c = await prof(caller), t = await prof(id);
  if (!c || !c.is_active || !["owner", "admin"].includes(c.role)) return res(403, { error: "Bukan admin" });
  if (!t) return res(404, { error: "Akun tidak ditemukan" });
  if (id === caller || t.role === "owner" || (t.role === "admin" && c.role !== "owner")) return res(403, { error: "Akun ini tidak boleh dihapus" });
  const d = await fetch(U + "/auth/v1/admin/users/" + encodeURIComponent(id), { method: "DELETE", headers: h });
  return d.ok ? res(200, { ok: true }) : res(502, { error: "Gagal menghapus" });
};
