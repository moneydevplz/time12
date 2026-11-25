const S = "https://bukeabrzlgcwzwtzmwld.supabase.co/functions/v1/mcp-oauth";
export default {
  fetch(req, env) {
    const u = new URL(req.url), p = u.pathname;
    if (p === "/mcp" || p.startsWith("/mcp/")) return fetch(new Request(S + p.slice(4) + u.search, req));
    if (p.startsWith("/.well-known/")) return fetch(new Request(S + p + u.search, req));
    return env.ASSETS.fetch(req);
  },
};