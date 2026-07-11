// algorithmic-arts-community worker — Google-SSO-gated proxy for
// comments on content in the Algorithmic Arts imprint. Every piece
// of content is one GitHub Issue in its own content repo (e.g.
// Binary-Blender/secret-life-of-ai/issues/1 for the album's comment
// thread); comments on that piece = comments on that Issue. Same
// Google identity + bot-attribution shape as the Foundry community
// worker, but the target (owner, repo, issue) travels with each
// request instead of being hard-coded.
//
// Reads are unauthenticated. Writes require a valid Google ID token
// whose `aud` matches one of the allowlisted client IDs.

interface Env {
  /** Classic PAT — bot posting on any Binary-Blender content repo. */
  GITHUB_TOKEN: string;
  /** Comma-separated allowlist of Google OAuth client IDs. */
  GOOGLE_CLIENT_IDS: string;
  /** KV: per-user like state + per-content counter for the ♡ button. */
  AA_LIKES: KVNamespace;
  /** KV: user-authored links between content items ("this reminded me of…"). */
  AA_LINKS: KVNamespace;
  /** KV: cached responses from external content sources (RSS / YouTube / etc.). */
  AA_EXTERNAL: KVNamespace;
  /** Optional: YouTube Data API v3 key. If unset, /api/external?type=youtube-channel returns 503. */
  YOUTUBE_API_KEY?: string;
  /** Optional: Spotify Developer app credentials for Client Credentials flow. */
  SPOTIFY_CLIENT_ID?: string;
  SPOTIFY_CLIENT_SECRET?: string;
  /** Optional: the imprint's Bluesky handle + app password for outbound (POSSE) syndication. */
  BLUESKY_HANDLE?: string;
  BLUESKY_APP_PASSWORD?: string;
}

const COMMENTS_PREFIX = "/api/comments";
const LIKES_PREFIX    = "/api/likes";
const REGISTER_PREFIX = "/api/register";
const LINKS_PREFIX    = "/api/links";
const EXTERNAL_PREFIX = "/api/external";
const PUBLISH_PREFIX  = "/api/publish";
const FEED_PREFIX     = "/api/feed";

// Owned posts (POSSE origin) live in posts.json at the root of the content repo —
// git-as-database, same shape as creators.json. The canonical URL of every post
// points back to the owned site; the silos only ever get syndicated copies.
const POSTS_FILE_PATH = "posts.json";
const SITE_BASE       = "https://algorithmic-arts.binary-blender.com";

const INDEX_REPO_OWNER = "Binary-Blender";
const INDEX_REPO_NAME  = "algorithmic-arts-index";
const INDEX_FILE_PATH  = "creators.json";

const VALID_CREATOR_TYPES = new Set(["author", "musician", "artist", "photographer", "filmmaker", "band"]);
const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;
const REPO_RE = /^([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)$/;

// Repos the platform recognizes. Anything not on this list gets 403 —
// the bot won't post to arbitrary repos even if someone crafts a request.
// Every new creator repo goes here; content_slug is stable per repo.
const REPO_ALLOWLIST: Record<string, { owner: string; repo: string }> = {
  "secret-life-of-ai":            { owner: "Binary-Blender", repo: "secret-life-of-ai" },
  "vela-works":                   { owner: "Binary-Blender", repo: "vela-works" },
  "soren-vael-works":             { owner: "Binary-Blender", repo: "soren-vael-works" },
  "aiwinwin-books":               { owner: "Binary-Blender", repo: "aiwinwin-books" },
  "algorithmic-arts-books":       { owner: "Binary-Blender", repo: "algorithmic-arts-books" },
  "algorithmic-arts-community":   { owner: "Binary-Blender", repo: "algorithmic-arts-community" },
};

const ALLOWED_ORIGINS = new Set([
  "https://net.binary-blender.com",
  "https://algorithmic-arts.binary-blender.com",
  "https://aiwinwin.binary-blender.com",
  "http://localhost:5173",
  "http://localhost:8788",
  "http://127.0.0.1:5173",
]);

// ─── Entry point ────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return preflight(request);
    const isComments = url.pathname.startsWith(COMMENTS_PREFIX);
    const isLikes    = url.pathname.startsWith(LIKES_PREFIX);
    const isRegister = url.pathname.startsWith(REGISTER_PREFIX);
    const isLinks    = url.pathname.startsWith(LINKS_PREFIX);
    const isExternal = url.pathname.startsWith(EXTERNAL_PREFIX);
    const isPublish  = url.pathname.startsWith(PUBLISH_PREFIX);
    const isFeed     = url.pathname.startsWith(FEED_PREFIX);
    if (!isComments && !isLikes && !isRegister && !isLinks && !isExternal && !isPublish && !isFeed) {
      return new Response("not found", { status: 404 });
    }

    const origin = request.headers.get("Origin");
    if (origin !== null && !ALLOWED_ORIGINS.has(origin)) {
      return jsonError(403, `forbidden origin: ${origin}`);
    }

    try {
      return withCors(await route(request, env, url), origin);
    } catch (e) {
      console.error("[aa-community] unhandled:", e);
      return withCors(jsonError(500, e instanceof Error ? e.message : String(e)), origin);
    }
  },
};

// ─── Routing ────────────────────────────────────────────────────────────────

async function route(request: Request, env: Env, url: URL): Promise<Response> {
  // ── /api/comments ────────────────────────────────────────────────
  if (url.pathname.startsWith(COMMENTS_PREFIX)) {
    const suffix = url.pathname.slice(COMMENTS_PREFIX.length);
    if (suffix === "/ping") {
      return new Response("pong", { status: 200, headers: { "Content-Type": "text/plain" } });
    }
    if (request.method === "GET"  && suffix === "") return listComments(env, url);
    if (request.method === "POST" && suffix === "") return postComment(request, env);
    return jsonError(404, `no route: ${request.method} /api/comments${suffix}`);
  }
  // ── /api/likes ──────────────────────────────────────────────────
  if (url.pathname.startsWith(LIKES_PREFIX)) {
    const suffix = url.pathname.slice(LIKES_PREFIX.length);
    if (request.method === "GET"  && suffix === "") return getLikes(env, url);
    if (request.method === "POST" && suffix === "") return toggleLike(request, env);
    return jsonError(404, `no route: ${request.method} /api/likes${suffix}`);
  }
  // ── /api/register ───────────────────────────────────────────────
  if (url.pathname.startsWith(REGISTER_PREFIX)) {
    const suffix = url.pathname.slice(REGISTER_PREFIX.length);
    if (request.method === "POST" && suffix === "") return registerCreator(request, env);
    return jsonError(404, `no route: ${request.method} /api/register${suffix}`);
  }
  // ── /api/external ───────────────────────────────────────────────
  if (url.pathname.startsWith(EXTERNAL_PREFIX)) {
    const suffix = url.pathname.slice(EXTERNAL_PREFIX.length);
    if (request.method === "GET" && suffix === "") return getExternal(env, url);
    return jsonError(404, `no route: ${request.method} /api/external${suffix}`);
  }
  // ── /api/links ──────────────────────────────────────────────────
  if (url.pathname.startsWith(LINKS_PREFIX)) {
    const suffix = url.pathname.slice(LINKS_PREFIX.length);
    if (request.method === "GET"    && suffix === "") return listLinks(env, url);
    if (request.method === "POST"   && suffix === "") return createLink(request, env);
    const delMatch = /^\/([^\/]+)$/.exec(suffix);
    if (request.method === "DELETE" && delMatch)      return deleteLink(request, env, delMatch[1]);
    return jsonError(404, `no route: ${request.method} /api/links${suffix}`);
  }
  // ── /api/publish ────────────────────────────────────────────────
  if (url.pathname.startsWith(PUBLISH_PREFIX)) {
    const suffix = url.pathname.slice(PUBLISH_PREFIX.length);
    if (request.method === "POST" && suffix === "") return publishPost(request, env);
    return jsonError(404, `no route: ${request.method} /api/publish${suffix}`);
  }
  // ── /api/feed ───────────────────────────────────────────────────
  if (url.pathname.startsWith(FEED_PREFIX)) {
    const suffix = url.pathname.slice(FEED_PREFIX.length);
    if (request.method === "GET" && suffix === "") return getFeed(env, url);
    return jsonError(404, `no route: ${request.method} /api/feed${suffix}`);
  }
  return jsonError(404, `no route: ${request.method} ${url.pathname}`);
}

// ─── Cross-medium links ─────────────────────────────────────────────────────
//
// A link is a user-authored connection between two content items on the
// platform ("this reminded me of..."). Both endpoints must be community
// content items validated against the roster + their manifests.
//
// Storage (AA_LINKS):
//   link:<id>             → JSON  { id, from:{creator,content}, to:{creator,content},
//                                   note, sub, email, name, createdAt }
//   linkout:<F>:<id>      → id    (F = <fromCreator>/<fromContent>)
//   linkin:<T>:<id>       → id    (T = <toCreator>/<toContent>)
//
// id format: `<ms>-<random8>` — timestamp-prefixed so list() returns
// newest-last naturally, and we can slice to newest-first without an
// extra sort. Random suffix disambiguates same-ms creations.

// Link target: either a native Net content (creator+content) or an external URL.
interface NativeTarget   { creator: string; content: string; }
interface ExternalTarget { external: { url: string; title?: string; sourceName?: string; }; }
type LinkTarget = NativeTarget | ExternalTarget;

function isExternalTarget(t: LinkTarget): t is ExternalTarget {
  return typeof (t as ExternalTarget).external === "object" && (t as ExternalTarget).external !== null;
}

interface LinkRecord {
  id: string;
  from: NativeTarget;        // MVP: source is always native
  to:   LinkTarget;          // Target may be native OR external
  note: string;
  sub:  string;
  email: string;
  name: string;
  createdAt: string;
}

async function listLinks(env: Env, url: URL): Promise<Response> {
  const direction = url.searchParams.get("direction");
  const creator   = url.searchParams.get("creator");
  const content   = url.searchParams.get("content");
  if (direction !== "out" && direction !== "in") {
    return jsonError(400, "direction must be 'out' or 'in'");
  }
  if (!creator || !content) return jsonError(400, "creator and content required");

  const prefix = direction === "out"
    ? `linkout:${creator}/${content}:`
    : `linkin:${creator}/${content}:`;
  const listResp = await env.AA_LINKS.list({ prefix, limit: 500 });
  const ids = listResp.keys.map((k) => k.name.slice(prefix.length));
  // Read all link records in parallel
  const records = await Promise.all(ids.map((id) => env.AA_LINKS.get(`link:${id}`)));
  const links = records
    .map((r) => { try { return r ? JSON.parse(r) as LinkRecord : null; } catch { return null; } })
    .filter((r): r is LinkRecord => r !== null)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));  // newest first

  // Redact identifying details to avoid exposing email — only the display
  // name and a short sub hash come out. sub-full is present only on the
  // record we later use to authorize deletion.
  const publicLinks = links.map((r) => ({
    id: r.id,
    from: r.from,
    to:   r.to,
    note: r.note,
    createdAt: r.createdAt,
    author: { name: r.name, subHash: r.sub.slice(-8) },
  }));
  return jsonOk({ links: publicLinks });
}

async function createLink(request: Request, env: Env): Promise<Response> {
  const payload = await parseJson(request);
  if (!payload) return jsonError(400, "invalid JSON body");
  const p = payload as {
    googleIdToken?: string;
    from?: { creator?: string; content?: string };
    to?:   { creator?: string; content?: string; external?: { url?: string; title?: string; sourceName?: string } };
    note?: string;
  };
  if (typeof p.googleIdToken !== "string") return jsonError(400, "missing googleIdToken");
  if (!p.from || typeof p.from.creator !== "string" || typeof p.from.content !== "string") return jsonError(400, "missing/invalid 'from' target");
  const note = typeof p.note === "string" ? p.note.trim().slice(0, 500) : "";

  const identity = await verifyGoogleToken(p.googleIdToken, env);
  if (!identity) return jsonError(401, "invalid or expired Google token");

  // Validate source — always native
  const fromV = await validateCommunityTarget(p.from.creator, p.from.content);
  if ("error" in fromV) return jsonError(fromV.status ?? 400, `from: ${fromV.error}`);

  // Detect target shape — native (creator+content) or external ({url})
  let toResolved: LinkTarget;
  if (p.to && p.to.external && typeof p.to.external.url === "string") {
    // External target
    const raw = p.to.external.url.trim();
    let parsed: URL;
    try { parsed = new URL(raw); } catch { return jsonError(400, "to.external.url is not a valid URL"); }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return jsonError(400, "to.external.url must be http/https");
    const title      = typeof p.to.external.title      === "string" ? p.to.external.title.trim().slice(0, 200)      : "";
    const sourceName = typeof p.to.external.sourceName === "string" ? p.to.external.sourceName.trim().slice(0, 100) : "";
    toResolved = { external: { url: raw, ...(title ? { title } : {}), ...(sourceName ? { sourceName } : {}) } };
  } else if (p.to && typeof p.to.creator === "string" && typeof p.to.content === "string") {
    // Native target — validate
    if (p.from.creator === p.to.creator && p.from.content === p.to.content) {
      return jsonError(400, "can't link a content to itself");
    }
    const toV = await validateCommunityTarget(p.to.creator, p.to.content);
    if ("error" in toV) return jsonError(toV.status ?? 400, `to: ${toV.error}`);
    toResolved = { creator: p.to.creator, content: p.to.content };
  } else {
    return jsonError(400, "missing/invalid 'to' target — provide {creator, content} for native or {external:{url}} for external");
  }

  // Duplicate check: same author, same from, same normalized to → 409
  const outPrefix = `linkout:${p.from.creator}/${p.from.content}:`;
  const existing = await env.AA_LINKS.list({ prefix: outPrefix, limit: 500 });
  for (const key of existing.keys) {
    const id = key.name.slice(outPrefix.length);
    const rec = await env.AA_LINKS.get(`link:${id}`);
    if (!rec) continue;
    try {
      const r = JSON.parse(rec) as LinkRecord;
      if (r.sub !== identity.sub) continue;
      const same = isExternalTarget(toResolved) && isExternalTarget(r.to)
        ? r.to.external.url === toResolved.external.url
        : !isExternalTarget(toResolved) && !isExternalTarget(r.to)
          && r.to.creator === toResolved.creator && r.to.content === toResolved.content;
      if (same) return jsonError(409, "you already created this link");
    } catch { /* ignore */ }
  }

  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const record: LinkRecord = {
    id,
    from: { creator: p.from.creator, content: p.from.content },
    to:   toResolved,
    note,
    sub:   identity.sub,
    email: identity.email,
    name:  identity.name,
    createdAt: new Date().toISOString(),
  };
  await env.AA_LINKS.put(`link:${id}`, JSON.stringify(record));
  await env.AA_LINKS.put(`linkout:${p.from.creator}/${p.from.content}:${id}`, id);
  // Reverse index only for native targets — external URLs have unbounded
  // namespace and no meaningful reverse query.
  if (!isExternalTarget(toResolved)) {
    await env.AA_LINKS.put(`linkin:${toResolved.creator}/${toResolved.content}:${id}`, id);
  }
  return jsonOk({ link: {
    id, from: record.from, to: record.to, note, createdAt: record.createdAt,
    author: { name: identity.name, subHash: identity.sub.slice(-8) },
  } });
}

async function deleteLink(request: Request, env: Env, linkId: string): Promise<Response> {
  const payload = await parseJson(request);
  if (!payload) return jsonError(400, "invalid JSON body");
  const p = payload as { googleIdToken?: string };
  if (typeof p.googleIdToken !== "string") return jsonError(400, "missing googleIdToken");
  const identity = await verifyGoogleToken(p.googleIdToken, env);
  if (!identity) return jsonError(401, "invalid or expired Google token");

  const rec = await env.AA_LINKS.get(`link:${linkId}`);
  if (!rec) return jsonError(404, "link not found");
  let record: LinkRecord;
  try { record = JSON.parse(rec) as LinkRecord; }
  catch { return jsonError(500, "corrupt link record"); }
  if (record.sub !== identity.sub) return jsonError(403, "only the author can delete this link");

  await env.AA_LINKS.delete(`link:${linkId}`);
  await env.AA_LINKS.delete(`linkout:${record.from.creator}/${record.from.content}:${linkId}`);
  // Reverse index only exists for native targets — external targets skipped this on create.
  if (!isExternalTarget(record.to)) {
    await env.AA_LINKS.delete(`linkin:${record.to.creator}/${record.to.content}:${linkId}`);
  }
  return jsonOk({ deleted: linkId });
}

// ─── Register (self-serve creator onboarding) ───────────────────────────────
//
// POST /api/register { googleIdToken, repo }
//   where repo is "owner/name" (or a github.com URL we'll extract from)
//
// Flow:
//   1. Verify Google JWT — get the caller's identity
//   2. Fetch the repo's .algorithmic-arts.json via GitHub raw
//   3. Validate the manifest schema
//   4. GET the current creators.json + SHA from the index repo
//   5. Check slug uniqueness against the existing roster
//   6. Append the new creator with registeredBy + registeredAt
//   7. PUT the updated file back (as the platform bot)
//   8. Return the new creator record so the wizard can render success
//
// Manifest expected at <repo>/.algorithmic-arts.json:
//   {
//     "creator": {
//       "name":     "...",             // required
//       "slug":     "...",             // required, unique; [a-z0-9][a-z0-9-]{1,39}
//       "types":    ["author", ...],   // required; ⊂ VALID_CREATOR_TYPES
//       "bio":      "...",             // optional
//       "portrait": "path/in/repo",    // optional; converted to raw URL server-side
//       "register": "...",             // optional short subtitle
//       "epigraph": "..."              // optional single-quote line
//     }
//   }

interface CreatorManifest {
  name: string;
  slug: string;
  types: string[];
  bio?: string;
  portrait?: string;
  register?: string;
  epigraph?: string;
}

interface CreatorRecord extends CreatorManifest {
  repo: string;             // "owner/name"
  registeredBy: string;
  registeredAt: string;
}

async function registerCreator(request: Request, env: Env): Promise<Response> {
  const payload = await parseJson(request);
  if (!payload) return jsonError(400, "invalid JSON body");
  const { googleIdToken, repo } = payload as { googleIdToken?: string; repo?: string };
  if (typeof googleIdToken !== "string") return jsonError(400, "missing googleIdToken");
  if (typeof repo !== "string" || repo.trim().length === 0) return jsonError(400, "missing repo");

  const identity = await verifyGoogleToken(googleIdToken, env);
  if (!identity) return jsonError(401, "invalid or expired Google token");

  // Normalize repo — accept full URL or owner/name
  let repoPath = repo.trim();
  const urlMatch = /github\.com\/([^\/]+\/[^\/#?\s]+)/.exec(repoPath);
  if (urlMatch) repoPath = urlMatch[1];
  repoPath = repoPath.replace(/\.git$/, "").replace(/^\/+|\/+$/g, "");
  if (!REPO_RE.test(repoPath)) return jsonError(400, `repo must be owner/name (got: ${repoPath.slice(0, 100)})`);
  const [owner, name] = repoPath.split("/");

  // Fetch the manifest — use HEAD (main or master, follows default branch)
  const manifestUrl = `https://raw.githubusercontent.com/${owner}/${name}/HEAD/.algorithmic-arts.json`;
  const mfResp = await fetch(manifestUrl);
  if (mfResp.status === 404) {
    return jsonError(404, `no .algorithmic-arts.json at root of ${repoPath} — add the manifest and try again`);
  }
  if (!mfResp.ok) {
    return jsonError(mfResp.status, `couldn't fetch manifest: HTTP ${mfResp.status}`);
  }
  let manifestJson: unknown;
  try { manifestJson = await mfResp.json(); }
  catch { return jsonError(400, ".algorithmic-arts.json is not valid JSON"); }
  const creatorRaw = (manifestJson as { creator?: unknown }).creator;
  if (!creatorRaw || typeof creatorRaw !== "object") {
    return jsonError(400, "manifest missing top-level `creator` object");
  }
  const validation = validateCreator(creatorRaw as Record<string, unknown>);
  if ("error" in validation) return jsonError(400, validation.error);
  const creator = validation.value;

  // Fetch current creators.json + SHA
  const idxResp = await ghFetch(env, `https://api.github.com/repos/${INDEX_REPO_OWNER}/${INDEX_REPO_NAME}/contents/${INDEX_FILE_PATH}`);
  if (!idxResp.ok) return jsonError(500, `couldn't read the index: HTTP ${idxResp.status}`);
  const idxFile = await idxResp.json() as { content: string; sha: string; encoding: string };
  if (idxFile.encoding !== "base64") return jsonError(500, `index file has unexpected encoding: ${idxFile.encoding}`);
  const idxContent = atob(idxFile.content.replace(/\n/g, ""));
  let roster: CreatorRecord[];
  try { roster = JSON.parse(idxContent) as CreatorRecord[]; }
  catch { return jsonError(500, "index file is not valid JSON"); }

  // Slug uniqueness
  if (roster.some((c) => c.slug === creator.slug)) {
    return jsonError(409, `slug "${creator.slug}" is already registered — pick a different slug in your manifest`);
  }
  // Also prevent double-registering the same repo
  if (roster.some((c) => c.repo === repoPath)) {
    return jsonError(409, `repo ${repoPath} is already registered`);
  }

  // Convert relative portrait path to raw URL
  if (creator.portrait && !/^https?:\/\//.test(creator.portrait)) {
    creator.portrait = `https://raw.githubusercontent.com/${owner}/${name}/HEAD/${creator.portrait.replace(/^\/+/, "")}`;
  }

  const now = new Date(mfResp.headers.get("date") ?? "").toISOString();
  const newRecord: CreatorRecord = {
    ...creator,
    repo: repoPath,
    registeredBy: identity.email,
    registeredAt: now === "Invalid Date" ? "" : now,
  };
  roster.push(newRecord);

  // Commit the update
  const newContent = btoa(JSON.stringify(roster, null, 2) + "\n");
  const putResp = await ghFetch(env, `https://api.github.com/repos/${INDEX_REPO_OWNER}/${INDEX_REPO_NAME}/contents/${INDEX_FILE_PATH}`, {
    method: "PUT",
    body: JSON.stringify({
      message: `Register ${creator.slug} (${creator.name})\n\nvia /create by ${identity.email}`,
      content: newContent,
      sha: idxFile.sha,
    }),
  });
  if (!putResp.ok) return passUpstreamError(putResp);

  return jsonOk({ creator: newRecord, rosterSize: roster.length });
}

function validateCreator(raw: Record<string, unknown>): { error: string } | { value: CreatorManifest } {
  const name = raw.name;
  const slug = raw.slug;
  const types = raw.types;
  if (typeof name !== "string" || name.trim().length === 0) return { error: "creator.name is required" };
  if (typeof slug !== "string" || !SLUG_RE.test(slug))       return { error: "creator.slug must match [a-z0-9][a-z0-9-]{1,39}" };
  if (!Array.isArray(types) || types.length === 0)           return { error: "creator.types must be a non-empty array" };
  for (const t of types) {
    if (typeof t !== "string" || !VALID_CREATOR_TYPES.has(t)) {
      return { error: `unknown creator type "${t}" — valid: ${[...VALID_CREATOR_TYPES].join(", ")}` };
    }
  }
  const bio      = typeof raw.bio      === "string" ? raw.bio      : undefined;
  const portrait = typeof raw.portrait === "string" ? raw.portrait : undefined;
  const register = typeof raw.register === "string" ? raw.register : undefined;
  const epigraph = typeof raw.epigraph === "string" ? raw.epigraph : undefined;
  return {
    value: {
      name: name.trim().slice(0, 120),
      slug,
      types,
      ...(bio      ? { bio:      bio.trim().slice(0, 800) }      : {}),
      ...(portrait ? { portrait: portrait.trim() }               : {}),
      ...(register ? { register: register.trim().slice(0, 120) } : {}),
      ...(epigraph ? { epigraph: epigraph.trim().slice(0, 240) } : {}),
    },
  };
}

// ─── Likes (KV-backed) ──────────────────────────────────────────────────────
//
// Storage:
//   like:<content>:<issue>:<sub>   → epoch ms of the like (presence == liked)
//   count:<content>:<issue>        → total count as a string
//
// Read GET /api/likes?content=X&issue=N[&sub=Y] returns {count, liked}
// where `liked` is present only if a sub was supplied. This lets the
// frontend show the count to anonymous readers and highlight the button
// for the signed-in user in one round trip.
//
// Toggle POST /api/likes {googleIdToken, content, issue} flips the state
// and returns the new {count, liked}. KV writes are eventually consistent
// but per-key ordering is preserved.

async function getLikes(env: Env, url: URL): Promise<Response> {
  const kp = await resolveKeyPrefixFromUrl(env, url);
  if ("error" in kp) return jsonError(kp.status ?? 400, kp.error);
  const sub = url.searchParams.get("sub");

  const countKey = `count:${kp.keyPrefix}`;
  const countStr = await env.AA_LIKES.get(countKey);
  const count = countStr ? Math.max(0, parseInt(countStr, 10)) : 0;

  const payload: { count: number; liked?: boolean } = { count };
  if (sub && sub.length > 0) {
    const likeKey = `like:${kp.keyPrefix}:${sub}`;
    const has = await env.AA_LIKES.get(likeKey);
    payload.liked = has !== null;
  }
  return jsonOk(payload);
}

async function toggleLike(request: Request, env: Env): Promise<Response> {
  const payload = await parseJson(request);
  if (!payload) return jsonError(400, "invalid JSON body");
  const { googleIdToken } = payload as { googleIdToken?: string };
  if (typeof googleIdToken !== "string") return jsonError(400, "missing googleIdToken");

  const identity = await verifyGoogleToken(googleIdToken, env);
  if (!identity) return jsonError(401, "invalid or expired Google token");

  const kp = await resolveKeyPrefixFromBody(env, payload as Record<string, unknown>);
  if ("error" in kp) return jsonError(kp.status ?? 400, kp.error);

  const likeKey  = `like:${kp.keyPrefix}:${identity.sub}`;
  const countKey = `count:${kp.keyPrefix}`;

  const existing = await env.AA_LIKES.get(likeKey);
  let count = Number((await env.AA_LIKES.get(countKey)) ?? "0") || 0;

  if (existing !== null) {
    await env.AA_LIKES.delete(likeKey);
    count = Math.max(0, count - 1);
    await env.AA_LIKES.put(countKey, String(count));
    return jsonOk({ count, liked: false });
  } else {
    await env.AA_LIKES.put(likeKey, String(Date.now()));
    count = count + 1;
    await env.AA_LIKES.put(countKey, String(count));
    return jsonOk({ count, liked: true });
  }
}

// ─── Target resolution (studio vs community) ────────────────────────────────
//
// Two shapes converge here:
//   1. Studio hardcoded — {content, issue} where content ∈ REPO_ALLOWLIST
//      and issue is a specific pre-created GitHub Issue number. Legacy.
//   2. Community — {creator, contentSlug} where creator is a registered
//      slug from the central roster and contentSlug is a slug that must
//      appear in that creator's manifest.content[]. The GitHub issue is
//      resolved by label (content:<contentSlug>); lazy-created on first
//      comment POST.
//
// KV key namespaces are kept distinct so studio and community targets
// never collide even if slugs happen to match:
//   studio:    <content>:<issue>
//   community: community/<creator>/<contentSlug>

interface ResolvedTarget {
  owner: string;
  repo: string;
  /** null in community mode when no issue exists yet + we're not creating */
  issue: number | null;
  /** Content title for empty-thread rendering (community only) */
  contentTitle?: string;
}

interface ResolveError { error: string; status?: number; }

async function resolveFromUrl(env: Env, url: URL, createIfMissing: boolean): Promise<ResolvedTarget | ResolveError> {
  const contentKey  = url.searchParams.get("content");
  const issueParam  = url.searchParams.get("issue");
  const creator     = url.searchParams.get("creator");
  const contentSlug = url.searchParams.get("contentSlug");

  if (creator && contentSlug) {
    return resolveCommunity(env, creator, contentSlug, createIfMissing);
  }
  if (contentKey && issueParam) {
    return resolveStudio(contentKey, Number(issueParam));
  }
  return { error: "provide either (content, issue) or (creator, contentSlug)" };
}

async function resolveFromBody(env: Env, body: Record<string, unknown>, createIfMissing: boolean): Promise<ResolvedTarget | ResolveError> {
  const contentKey  = typeof body.content === "string" ? body.content : undefined;
  const issueNum    = typeof body.issue === "number" ? body.issue : undefined;
  const creator     = typeof body.creator === "string" ? body.creator : undefined;
  const contentSlug = typeof body.contentSlug === "string" ? body.contentSlug : undefined;

  if (creator && contentSlug) {
    return resolveCommunity(env, creator, contentSlug, createIfMissing);
  }
  if (contentKey && typeof issueNum === "number") {
    return resolveStudio(contentKey, issueNum);
  }
  return { error: "provide either (content, issue) or (creator, contentSlug)" };
}

function resolveStudio(contentKey: string, issue: number): ResolvedTarget | ResolveError {
  const repoRef = REPO_ALLOWLIST[contentKey];
  if (!repoRef) return { error: `unknown content slug: ${contentKey}`, status: 403 };
  if (!Number.isFinite(issue) || issue < 1) return { error: "issue must be a positive integer" };
  return { owner: repoRef.owner, repo: repoRef.repo, issue };
}

async function resolveCommunity(env: Env, creatorSlug: string, contentSlug: string, createIfMissing: boolean): Promise<ResolvedTarget | ResolveError> {
  const roster = await fetchRoster();
  if (!roster) return { error: "couldn't load the roster", status: 502 };
  const c = roster.find((x) => x.slug === creatorSlug);
  if (!c) return { error: `no creator with slug: ${creatorSlug}`, status: 404 };

  const [owner, repo] = c.repo.split("/");
  const manifest = await fetchManifest(c.repo);
  if (!manifest) return { error: `couldn't load manifest for ${c.repo}`, status: 502 };
  const content = (Array.isArray(manifest.content) ? manifest.content : []) as Array<{ slug?: string; title?: string }>;
  const item = content.find((i) => i.slug === contentSlug);
  if (!item) return { error: `no content "${contentSlug}" in ${c.repo}`, status: 404 };

  const label = `content:${contentSlug}`;
  const existing = await findContentIssue(env, owner, repo, label);
  if (existing !== null) {
    return { owner, repo, issue: existing, contentTitle: item.title ?? contentSlug };
  }
  if (!createIfMissing) {
    return { owner, repo, issue: null, contentTitle: item.title ?? contentSlug };
  }
  const created = await createContentIssue(env, owner, repo, contentSlug, item.title ?? contentSlug, creatorSlug);
  return { owner, repo, issue: created, contentTitle: item.title ?? contentSlug };
}

async function resolveKeyPrefixFromUrl(_env: Env, url: URL): Promise<{ keyPrefix: string } | ResolveError> {
  const contentKey  = url.searchParams.get("content");
  const issueParam  = url.searchParams.get("issue");
  const creator     = url.searchParams.get("creator");
  const contentSlug = url.searchParams.get("contentSlug");
  if (creator && contentSlug) {
    const validated = await validateCommunityTarget(creator, contentSlug);
    if ("error" in validated) return validated;
    return { keyPrefix: `community/${creator}/${contentSlug}` };
  }
  if (contentKey && issueParam) {
    const issue = Number(issueParam);
    if (!REPO_ALLOWLIST[contentKey]) return { error: `unknown content slug: ${contentKey}`, status: 403 };
    if (!Number.isFinite(issue) || issue < 1) return { error: "issue must be a positive integer" };
    return { keyPrefix: `${contentKey}:${issue}` };
  }
  return { error: "provide either (content, issue) or (creator, contentSlug)" };
}

async function resolveKeyPrefixFromBody(_env: Env, body: Record<string, unknown>): Promise<{ keyPrefix: string } | ResolveError> {
  const contentKey  = typeof body.content === "string" ? body.content : undefined;
  const issueNum    = typeof body.issue === "number" ? body.issue : undefined;
  const creator     = typeof body.creator === "string" ? body.creator : undefined;
  const contentSlug = typeof body.contentSlug === "string" ? body.contentSlug : undefined;
  if (creator && contentSlug) {
    const validated = await validateCommunityTarget(creator, contentSlug);
    if ("error" in validated) return validated;
    return { keyPrefix: `community/${creator}/${contentSlug}` };
  }
  if (contentKey && typeof issueNum === "number") {
    if (!REPO_ALLOWLIST[contentKey]) return { error: `unknown content slug: ${contentKey}`, status: 403 };
    return { keyPrefix: `${contentKey}:${issueNum}` };
  }
  return { error: "provide either (content, issue) or (creator, contentSlug)" };
}

async function validateCommunityTarget(creatorSlug: string, contentSlug: string): Promise<{ repo: string; title: string } | ResolveError> {
  const roster = await fetchRoster();
  if (!roster) return { error: "couldn't load the roster", status: 502 };
  const c = roster.find((x) => x.slug === creatorSlug);
  if (!c) return { error: `no creator with slug: ${creatorSlug}`, status: 404 };
  const manifest = await fetchManifest(c.repo);
  if (!manifest) return { error: `couldn't load manifest for ${c.repo}`, status: 502 };
  const content = (Array.isArray(manifest.content) ? manifest.content : []) as Array<{ slug?: string; title?: string }>;
  const item = content.find((i) => i.slug === contentSlug);
  if (!item) return { error: `no content "${contentSlug}" in ${c.repo}`, status: 404 };
  return { repo: c.repo, title: item.title ?? contentSlug };
}

// ─── Helpers for community resolution ──────────────────────────────────────

interface CachedRoster { fetchedAt: number; data: CreatorRecord[]; }
let rosterCache: CachedRoster | null = null;
const ROSTER_CACHE_MS = 60_000;

async function fetchRoster(): Promise<CreatorRecord[] | null> {
  if (rosterCache && Date.now() - rosterCache.fetchedAt < ROSTER_CACHE_MS) {
    return rosterCache.data;
  }
  const resp = await fetch(`https://raw.githubusercontent.com/${INDEX_REPO_OWNER}/${INDEX_REPO_NAME}/HEAD/${INDEX_FILE_PATH}?t=${Date.now()}`);
  if (!resp.ok) return null;
  try {
    const data = await resp.json() as CreatorRecord[];
    rosterCache = { fetchedAt: Date.now(), data };
    return data;
  } catch { return null; }
}

async function fetchManifest(repoPath: string): Promise<{ content?: unknown[] } | null> {
  const resp = await fetch(`https://raw.githubusercontent.com/${repoPath}/HEAD/.algorithmic-arts.json?t=${Date.now()}`);
  if (!resp.ok) return null;
  try { return await resp.json() as { content?: unknown[] }; }
  catch { return null; }
}

async function findContentIssue(env: Env, owner: string, repo: string, label: string): Promise<number | null> {
  const resp = await ghFetch(env, `https://api.github.com/repos/${owner}/${repo}/issues?labels=${encodeURIComponent(label)}&state=all&per_page=1`);
  if (!resp.ok) return null;
  const issues = await resp.json() as Array<{ number: number; pull_request?: unknown }>;
  const notPr = issues.find((i) => !i.pull_request);
  return notPr ? notPr.number : null;
}

async function createContentIssue(env: Env, owner: string, repo: string, contentSlug: string, title: string, creatorSlug: string): Promise<number> {
  const url = `https://net.binary-blender.com/creators/${encodeURIComponent(creatorSlug)}/${encodeURIComponent(contentSlug)}`;
  const resp = await ghFetch(env, `https://api.github.com/repos/${owner}/${repo}/issues`, {
    method: "POST",
    body: JSON.stringify({
      title: `Comments — ${title.slice(0, 200)}`,
      body:  `Comment thread for **${title}** at ${url}. Any comment posted there is added here as a reply, attributed to the Google user who posted it. Comment directly on GitHub if you prefer — same thread.`,
      labels: ["comments", `content:${contentSlug}`],
    }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`couldn't create content issue: HTTP ${resp.status} — ${text.slice(0, 300)}`);
  }
  const created = await resp.json() as { number: number };
  return created.number;
}

// ─── Read path (unauthenticated) ────────────────────────────────────────────

async function listComments(env: Env, url: URL): Promise<Response> {
  const target = await resolveFromUrl(env, url, /*createIfMissing*/ false);
  if ("error" in target) return jsonError(target.status ?? 400, target.error);

  // Community content with no issue yet — return an empty thread so the
  // UI can render "no comments yet, be first" without a round trip that
  // creates a stub issue on the creator's repo.
  if (target.issue === null) {
    return jsonOk({
      thread: {
        number: 0,
        title:  target.contentTitle ?? "",
        body:   "",
        createdAt: "",
        updatedAt: "",
        repoOwner: target.owner,
        repoName:  target.repo,
        htmlUrl:   `https://github.com/${target.owner}/${target.repo}`,
        replies:   [],
      },
    });
  }

  const [issueResp, commentsResp] = await Promise.all([
    ghFetch(env, `https://api.github.com/repos/${target.owner}/${target.repo}/issues/${target.issue}`),
    ghFetch(env, `https://api.github.com/repos/${target.owner}/${target.repo}/issues/${target.issue}/comments?per_page=100`),
  ]);
  if (!issueResp.ok)    return passUpstreamError(issueResp);
  if (!commentsResp.ok) return passUpstreamError(commentsResp);
  const iss = await issueResp.json() as {
    number: number; title: string; body: string | null;
    created_at: string; updated_at: string;
  };
  const comments = await commentsResp.json() as Array<{
    id: number; body: string | null;
    created_at: string; updated_at: string;
  }>;
  return jsonOk({
    thread: {
      number: iss.number,
      title:  iss.title,
      body:   iss.body ?? "",
      createdAt: iss.created_at,
      updatedAt: iss.updated_at,
      repoOwner: target.owner,
      repoName:  target.repo,
      htmlUrl:   `https://github.com/${target.owner}/${target.repo}/issues/${iss.number}`,
      replies:   comments.map((c) => ({
        id: c.id,
        body: c.body ?? "",
        createdAt: c.created_at,
        updatedAt: c.updated_at,
      })),
    },
  });
}

// ─── Write path (Google JWT required) ───────────────────────────────────────

async function postComment(request: Request, env: Env): Promise<Response> {
  const payload = await parseJson(request);
  if (!payload) return jsonError(400, "invalid JSON body");
  const { googleIdToken, body } = payload as { googleIdToken?: string; body?: string };
  if (typeof googleIdToken !== "string") return jsonError(400, "missing googleIdToken");
  if (typeof body !== "string" || body.trim().length === 0) return jsonError(400, "missing body");
  if (body.length > 5000) return jsonError(413, "comment too long (max 5000)");

  const identity = await verifyGoogleToken(googleIdToken, env);
  if (!identity) return jsonError(401, "invalid or expired Google token");

  const target = await resolveFromBody(env, payload as Record<string, unknown>, /*createIfMissing*/ true);
  if ("error" in target) return jsonError(target.status ?? 400, target.error);
  if (target.issue === null) return jsonError(500, "issue resolution failed");

  const commentBody = attributedBody(identity, body);
  const ghResp = await ghFetch(env, `https://api.github.com/repos/${target.owner}/${target.repo}/issues/${target.issue}/comments`, {
    method: "POST",
    body: JSON.stringify({ body: commentBody }),
  });
  if (!ghResp.ok) return passUpstreamError(ghResp);
  const created = await ghResp.json() as { id: number; html_url: string; created_at: string; body: string };
  return jsonOk({
    id: created.id,
    htmlUrl: created.html_url,
    createdAt: created.created_at,
    body: created.body,
    issue: target.issue,
  });
}

// ─── External content sources (RSS / YouTube / etc.) ───────────────────────
//
// Aggregates content from platforms the creator's already on. Fetched
// server-side (bypasses CORS, hides API keys, caches aggressively) and
// returned in a normalized shape the frontend renders type-agnostic.
//
// Normalized shape:
//   {
//     type: "rss" | "youtube-channel" | "spotify-artist",
//     sourceName: "…",              — human-readable name of the feed/channel
//     sourceUrl:  "…",              — canonical link back to the source
//     items: [
//       { title, url, publishedAt, thumbnail?, description? }
//     ]
//   }
//
// Cache: keyed by type + source id. TTL 15 min via KV expirationTtl.

interface NormalizedExternal {
  type: string;
  sourceName: string;
  sourceUrl: string;
  items: Array<{
    title: string;
    url: string;
    publishedAt: string;
    thumbnail?: string;
    description?: string;
  }>;
}

async function getExternal(env: Env, url: URL): Promise<Response> {
  const type = url.searchParams.get("type");
  if (type === "rss")              return getRssFeed(env, url);
  if (type === "bluesky")          return getBlueskyFeed(env, url);
  if (type === "youtube-channel")  return getYoutubeChannel(env, url);
  if (type === "spotify-artist")   return getSpotifyArtist(env, url);
  return jsonError(400, `unsupported type "${type}" — supported: rss, bluesky, youtube-channel, spotify-artist`);
}

async function getRssFeed(env: Env, url: URL): Promise<Response> {
  const feedUrl = url.searchParams.get("url");
  if (!feedUrl) return jsonError(400, "url parameter required");
  let parsed: URL;
  try { parsed = new URL(feedUrl); } catch { return jsonError(400, "url is not a valid URL"); }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return jsonError(400, "url must be http or https");
  }

  const cacheKey = `rss:${feedUrl}`;
  const cached = await env.AA_EXTERNAL.get(cacheKey);
  if (cached) {
    try { return jsonOk(JSON.parse(cached)); }
    catch { /* fall through to refetch */ }
  }

  const resp = await fetch(feedUrl, {
    headers: {
      "User-Agent": "net.binary-blender.com feed aggregator",
      "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
    },
    cf: { cacheTtl: 60 },
  });
  if (!resp.ok) return jsonError(resp.status, `feed fetch failed: HTTP ${resp.status}`);
  const xml = await resp.text();
  const normalized = parseFeed(xml, feedUrl);
  await env.AA_EXTERNAL.put(cacheKey, JSON.stringify(normalized), { expirationTtl: 900 });
  return jsonOk(normalized);
}

// ── Bluesky (AT Protocol public API) ────────────────────────────────────────
// No auth required for reads. Endpoint: app.bsky.feed.getAuthorFeed with an
// actor handle. Feed items are posts; we normalize the first 200 chars of
// post.record.text as the "title" since Bluesky posts don't have titles.

async function getBlueskyFeed(env: Env, url: URL): Promise<Response> {
  const handle = url.searchParams.get("handle");
  if (!handle) return jsonError(400, "handle parameter required");
  const cleanHandle = handle.replace(/^@/, "").trim().toLowerCase();

  const cacheKey = `bluesky:${cleanHandle}`;
  const cached = await env.AA_EXTERNAL.get(cacheKey);
  if (cached) { try { return jsonOk(JSON.parse(cached)); } catch { /* refetch */ } }

  const apiUrl = `https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed?actor=${encodeURIComponent(cleanHandle)}&limit=20`;
  const resp = await fetch(apiUrl, { headers: { "Accept": "application/json" } });
  if (!resp.ok) return jsonError(resp.status, `Bluesky fetch failed: HTTP ${resp.status}`);
  interface BskyEntry {
    post: {
      uri: string;
      indexedAt: string;
      record?: { text?: string; createdAt?: string };
      embed?: {
        images?: Array<{ thumb?: string; fullsize?: string; alt?: string }>;
        media?:  { images?: Array<{ thumb?: string; fullsize?: string }> };
        external?: { thumb?: string; title?: string; description?: string };
      };
      author?: { handle?: string; displayName?: string };
    };
  }
  const data = await resp.json() as { feed?: BskyEntry[] };

  const items: NormalizedExternal["items"] = (data.feed || [])
    .filter((e) => e.post && e.post.uri)
    .map((e) => {
      const post = e.post;
      const rkey = post.uri.split("/").pop() ?? "";
      const webUrl = `https://bsky.app/profile/${cleanHandle}/post/${rkey}`;
      const text = (post.record?.text ?? "").trim();
      const title = text ? text.slice(0, 140) + (text.length > 140 ? "…" : "") : "(post without text)";
      const thumb =
        post.embed?.images?.[0]?.thumb ??
        post.embed?.media?.images?.[0]?.thumb ??
        post.embed?.external?.thumb ??
        "";
      const description = text.length > 140 ? text : "";
      return {
        title,
        url: webUrl,
        publishedAt: normalizeDate(post.record?.createdAt ?? post.indexedAt ?? ""),
        ...(thumb        ? { thumbnail: thumb } : {}),
        ...(description  ? { description: description.slice(0, 240) } : {}),
      };
    })
    .slice(0, 20);

  // Try to pull the display name from the first post's author
  const displayName = (data.feed?.[0]?.post?.author?.displayName || cleanHandle);
  const normalized: NormalizedExternal = {
    type: "bluesky",
    sourceName: displayName,
    sourceUrl: `https://bsky.app/profile/${cleanHandle}`,
    items,
  };
  await env.AA_EXTERNAL.put(cacheKey, JSON.stringify(normalized), { expirationTtl: 900 });
  return jsonOk(normalized);
}

// ── YouTube channel (Data API v3) ───────────────────────────────────────────
// Requires a YouTube API key in worker secrets. If unset, this route returns
// 503 with a clear message. Quota cost per listing: ~100 units. Free tier is
// 10 K/day; combined with a 15-min KV cache, hundreds of channels fit.

async function getYoutubeChannel(env: Env, url: URL): Promise<Response> {
  const channelId = url.searchParams.get("id");
  if (!channelId) return jsonError(400, "id parameter required (YouTube channel ID, e.g. UCxxxxxxxxxxxxxxxxxxxxxx)");
  if (!env.YOUTUBE_API_KEY) return jsonError(503, "YouTube support is not configured on this deployment (missing YOUTUBE_API_KEY)");

  const cacheKey = `youtube-channel:${channelId}`;
  const cached = await env.AA_EXTERNAL.get(cacheKey);
  if (cached) { try { return jsonOk(JSON.parse(cached)); } catch { /* refetch */ } }

  const apiUrl =
    `https://www.googleapis.com/youtube/v3/search` +
    `?part=snippet&channelId=${encodeURIComponent(channelId)}` +
    `&order=date&maxResults=20&type=video&key=${encodeURIComponent(env.YOUTUBE_API_KEY)}`;
  const resp = await fetch(apiUrl, { headers: { "Accept": "application/json" } });
  if (!resp.ok) {
    const text = await resp.text();
    return jsonError(resp.status, `YouTube fetch failed: HTTP ${resp.status} — ${text.slice(0, 300)}`);
  }
  interface YtItem {
    id: { videoId?: string };
    snippet: {
      title: string;
      description?: string;
      publishedAt: string;
      channelTitle?: string;
      thumbnails?: { default?: { url: string }; medium?: { url: string }; high?: { url: string } };
    };
  }
  const data = await resp.json() as { items?: YtItem[] };

  const items: NormalizedExternal["items"] = (data.items || [])
    .filter((i) => i.id.videoId)
    .map((i) => ({
      title: i.snippet.title,
      url:   `https://youtube.com/watch?v=${i.id.videoId}`,
      publishedAt: normalizeDate(i.snippet.publishedAt),
      ...(i.snippet.thumbnails?.medium?.url ? { thumbnail: i.snippet.thumbnails.medium.url } : {}),
      ...(i.snippet.description ? { description: htmlToText(i.snippet.description).slice(0, 240) } : {}),
    }))
    .slice(0, 20);

  const channelName = data.items?.[0]?.snippet?.channelTitle || channelId;
  const normalized: NormalizedExternal = {
    type: "youtube-channel",
    sourceName: channelName,
    sourceUrl: `https://youtube.com/channel/${channelId}`,
    items,
  };
  await env.AA_EXTERNAL.put(cacheKey, JSON.stringify(normalized), { expirationTtl: 900 });
  return jsonOk(normalized);
}

// ── Spotify artist (Client Credentials flow) ────────────────────────────────
// Needs a Spotify Developer app registered; client ID + secret in worker
// secrets. Client credentials flow gets a bearer token for public data
// (albums, top tracks, artist metadata). Token is ~1h; cached in KV.

async function getSpotifyToken(env: Env): Promise<string | null> {
  if (!env.SPOTIFY_CLIENT_ID || !env.SPOTIFY_CLIENT_SECRET) return null;
  const cached = await env.AA_EXTERNAL.get("spotify:token");
  if (cached) return cached;
  const basic = btoa(`${env.SPOTIFY_CLIENT_ID}:${env.SPOTIFY_CLIENT_SECRET}`);
  const resp = await fetch("https://accounts.spotify.com/api/token", {
    method: "POST",
    headers: {
      "Authorization": `Basic ${basic}`,
      "Content-Type":  "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });
  if (!resp.ok) return null;
  const data = await resp.json() as { access_token: string; expires_in: number };
  await env.AA_EXTERNAL.put("spotify:token", data.access_token, {
    expirationTtl: Math.max(60, data.expires_in - 60),  // refresh 1 min before real expiry
  });
  return data.access_token;
}

async function getSpotifyArtist(env: Env, url: URL): Promise<Response> {
  const artistId = url.searchParams.get("id");
  if (!artistId) return jsonError(400, "id parameter required (Spotify artist ID)");
  if (!env.SPOTIFY_CLIENT_ID || !env.SPOTIFY_CLIENT_SECRET) {
    return jsonError(503, "Spotify support is not configured on this deployment (missing SPOTIFY_CLIENT_ID / SPOTIFY_CLIENT_SECRET)");
  }

  const cacheKey = `spotify-artist:${artistId}`;
  const cached = await env.AA_EXTERNAL.get(cacheKey);
  if (cached) { try { return jsonOk(JSON.parse(cached)); } catch { /* refetch */ } }

  const token = await getSpotifyToken(env);
  if (!token) return jsonError(502, "couldn't obtain Spotify access token");

  const authH = { "Authorization": `Bearer ${token}`, "Accept": "application/json" };
  const [artistResp, albumsResp] = await Promise.all([
    fetch(`https://api.spotify.com/v1/artists/${encodeURIComponent(artistId)}`, { headers: authH }),
    fetch(`https://api.spotify.com/v1/artists/${encodeURIComponent(artistId)}/albums?limit=20&include_groups=album,single`, { headers: authH }),
  ]);
  if (!artistResp.ok) return jsonError(artistResp.status, `Spotify artist fetch failed: HTTP ${artistResp.status}`);
  if (!albumsResp.ok) return jsonError(albumsResp.status, `Spotify albums fetch failed: HTTP ${albumsResp.status}`);
  interface SpArtist { name: string; external_urls?: { spotify?: string }; images?: Array<{ url: string }>; }
  interface SpAlbum {
    name: string;
    album_type: string;
    total_tracks: number;
    release_date: string;
    external_urls?: { spotify?: string };
    images?: Array<{ url: string }>;
  }
  const artist = await artistResp.json() as SpArtist;
  const albums = await albumsResp.json() as { items?: SpAlbum[] };

  const items: NormalizedExternal["items"] = (albums.items || []).map((a) => ({
    title: a.name,
    url:   a.external_urls?.spotify || `https://open.spotify.com/artist/${artistId}`,
    publishedAt: normalizeDate(a.release_date),
    ...(a.images?.[0]?.url ? { thumbnail: a.images[0].url } : {}),
    description: `${a.album_type} · ${a.total_tracks} track${a.total_tracks === 1 ? "" : "s"}`,
  }));

  const normalized: NormalizedExternal = {
    type: "spotify-artist",
    sourceName: artist.name,
    sourceUrl:  artist.external_urls?.spotify || `https://open.spotify.com/artist/${artistId}`,
    items,
  };
  await env.AA_EXTERNAL.put(cacheKey, JSON.stringify(normalized), { expirationTtl: 900 });
  return jsonOk(normalized);
}

// ── Feed parser — handles RSS 2.0 and Atom ──────────────────────────────────
// Uses regex extraction rather than DOM parsing. Works because feeds are
// well-defined enough that greedy nesting isn't a real problem; the trade-off
// is that we won't handle deeply malformed feeds. Acceptable for a public
// aggregator — malformed feeds surface as no-items rather than crashes.

function parseFeed(xml: string, sourceUrl: string): NormalizedExternal {
  const isAtom = /<feed\b[^>]*xmlns=["']http:\/\/www\.w3\.org\/2005\/Atom["']/.test(xml) ||
                 /<feed\b[^>]*>/.test(xml) && !/<rss\b/.test(xml);

  if (isAtom) return parseAtom(xml, sourceUrl);
  return parseRss20(xml, sourceUrl);
}

function parseRss20(xml: string, sourceUrl: string): NormalizedExternal {
  const channelMatch = xml.match(/<channel\b[^>]*>([\s\S]*?)<\/channel>/i);
  const channelBody = channelMatch ? channelMatch[1] : xml;

  const feedTitle = firstTag(channelBody.replace(/<item\b[\s\S]*/i, ""), "title") || sourceUrl;
  const feedLink  = firstTag(channelBody.replace(/<item\b[\s\S]*/i, ""), "link")  || sourceUrl;

  const items: NormalizedExternal["items"] = [];
  const itemRegex = /<item\b[^>]*>([\s\S]*?)<\/item>/gi;
  let m: RegExpExecArray | null;
  while ((m = itemRegex.exec(xml)) !== null) {
    const body = m[1];
    const title = firstTag(body, "title");
    const link  = firstTag(body, "link");
    const desc  = firstTag(body, "description");
    const pub   = firstTag(body, "pubDate") || firstTag(body, "dc:date");
    const thumb = extractThumbnail(body);
    if (!title || !link) continue;
    items.push({
      title:       decodeEntities(title.trim()),
      url:         decodeEntities(link.trim()),
      publishedAt: normalizeDate(pub),
      ...(desc  ? { description: htmlToText(desc).slice(0, 240) } : {}),
      ...(thumb ? { thumbnail: thumb } : {}),
    });
    if (items.length >= 20) break;
  }
  return {
    type: "rss",
    sourceName: decodeEntities(feedTitle.trim()),
    sourceUrl:  decodeEntities(feedLink.trim()) || sourceUrl,
    items,
  };
}

function parseAtom(xml: string, sourceUrl: string): NormalizedExternal {
  const feedHead = xml.replace(/<entry\b[\s\S]*/i, "");
  const feedTitle = firstTag(feedHead, "title") || sourceUrl;
  // Atom <link href="…" rel="alternate" /> — pick the first alternate-or-plain
  const feedLinkMatch = feedHead.match(/<link\b([^>]*)\/?>/i);
  const feedLinkAttr  = feedLinkMatch ? feedLinkMatch[1] : "";
  const feedLink = attr(feedLinkAttr, "href") || sourceUrl;

  const items: NormalizedExternal["items"] = [];
  const entryRegex = /<entry\b[^>]*>([\s\S]*?)<\/entry>/gi;
  let m: RegExpExecArray | null;
  while ((m = entryRegex.exec(xml)) !== null) {
    const body = m[1];
    const title = firstTag(body, "title");
    // In Atom, <link href="…" /> is common; sometimes multiple <link> — take the alternate or first
    const linkMatches = [...body.matchAll(/<link\b([^>]*)\/?>/gi)];
    let link = "";
    for (const lm of linkMatches) {
      const attrs = lm[1];
      const rel = attr(attrs, "rel") || "alternate";
      const href = attr(attrs, "href");
      if (href && rel === "alternate") { link = href; break; }
      if (href && !link) link = href;
    }
    if (!link) link = firstTag(body, "link");   // some feeds do text link
    const summary = firstTag(body, "summary") || firstTag(body, "content");
    const pub = firstTag(body, "published") || firstTag(body, "updated");
    const thumb = extractThumbnail(body);
    if (!title || !link) continue;
    items.push({
      title:       decodeEntities(title.trim()),
      url:         decodeEntities(link.trim()),
      publishedAt: normalizeDate(pub),
      ...(summary ? { description: htmlToText(summary).slice(0, 240) } : {}),
      ...(thumb   ? { thumbnail: thumb } : {}),
    });
    if (items.length >= 20) break;
  }
  return {
    type: "rss",   // atom is still rendered as feed-shape for the UI
    sourceName: decodeEntities(feedTitle.trim()),
    sourceUrl:  decodeEntities(feedLink.trim()) || sourceUrl,
    items,
  };
}

function firstTag(xml: string, tag: string): string {
  const re = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i");
  const m = xml.match(re);
  if (!m) return "";
  return m[1].replace(/^<!\[CDATA\[|\]\]>$/g, "").trim();
}

function attr(attrs: string, name: string): string {
  const m = attrs.match(new RegExp(`\\b${name}=["']([^"']*)["']`, "i"));
  return m ? m[1] : "";
}

function extractThumbnail(itemBody: string): string {
  // media:thumbnail / media:content
  const mediaThumb = itemBody.match(/<media:thumbnail\b([^>]*)\/?>/i);
  if (mediaThumb) {
    const url = attr(mediaThumb[1], "url");
    if (url) return url;
  }
  const mediaContent = itemBody.match(/<media:content\b([^>]*)\/?>/i);
  if (mediaContent) {
    const url = attr(mediaContent[1], "url");
    if (url) return url;
  }
  // enclosure with image type
  const enclosure = itemBody.match(/<enclosure\b([^>]*)\/?>/i);
  if (enclosure) {
    const url = attr(enclosure[1], "url");
    const type = attr(enclosure[1], "type");
    if (url && (!type || type.startsWith("image/"))) return url;
  }
  // First <img src=""> in description/content
  const imgMatch = itemBody.match(/<img\b[^>]*src=["']([^"']+)["']/i);
  if (imgMatch) return imgMatch[1];
  return "";
}

function htmlToText(html: string): string {
  return decodeEntities(html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim());
}

function decodeEntities(s: string): string {
  return s
    .replace(/&amp;/g,  "&")
    .replace(/&lt;/g,   "<")
    .replace(/&gt;/g,   ">")
    .replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'")
    .replace(/&#39;/g,  "'")
    .replace(/&#8217;/g, "'")
    .replace(/&#8216;/g, "'")
    .replace(/&#8220;/g, "\"")
    .replace(/&#8221;/g, "\"")
    .replace(/&nbsp;/g, " ")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)));
}

function normalizeDate(raw: string): string {
  if (!raw) return "";
  const trimmed = raw.trim();
  const d = new Date(trimmed);
  if (isNaN(d.getTime())) return trimmed;   // preserve if unparseable
  return d.toISOString();
}

// ─── Google JWT verification ────────────────────────────────────────────────
// RS256 signature check via WebCrypto + exp/aud/iss claims. Same pattern
// as the Foundry community worker — JWKS cached in-worker for the duration
// of an invocation. Cold-start optimization; Workers don't share memory.

interface GoogleIdentity {
  sub: string;
  email: string;
  name: string;
  picture?: string;
}

const GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v3/certs";

interface JWK {
  kid: string; kty: string; alg: string; n: string; e: string; use: string;
}

let jwksCache: { keys: JWK[]; fetchedAt: number } | null = null;

async function getGoogleJwks(): Promise<JWK[]> {
  if (jwksCache && Date.now() - jwksCache.fetchedAt < 3_600_000) {
    return jwksCache.keys;
  }
  const resp = await fetch(GOOGLE_CERTS_URL);
  if (!resp.ok) throw new Error(`failed to fetch Google JWKS: ${resp.status}`);
  const data = await resp.json() as { keys: JWK[] };
  jwksCache = { keys: data.keys, fetchedAt: Date.now() };
  return data.keys;
}

function base64UrlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function decodeJwtPart(s: string): unknown {
  const bytes = base64UrlDecode(s);
  return JSON.parse(new TextDecoder().decode(bytes));
}

async function verifyGoogleToken(jwt: string, env: Env): Promise<GoogleIdentity | null> {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, signatureB64] = parts;

  let header: { alg?: string; kid?: string };
  let payload: { iss?: string; aud?: string; exp?: number; email?: string; name?: string; sub?: string; picture?: string };
  try {
    header  = decodeJwtPart(headerB64)  as typeof header;
    payload = decodeJwtPart(payloadB64) as typeof payload;
  } catch {
    return null;
  }

  if (payload.iss !== "https://accounts.google.com" && payload.iss !== "accounts.google.com") return null;
  const allowed = env.GOOGLE_CLIENT_IDS.split(",").map((s) => s.trim()).filter(Boolean);
  if (!payload.aud || !allowed.includes(payload.aud)) return null;
  if (typeof payload.exp !== "number" || payload.exp * 1000 < Date.now()) return null;
  if (header.alg !== "RS256" || !header.kid) return null;

  const keys = await getGoogleJwks();
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) return null;

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const signature = base64UrlDecode(signatureB64);
  const signed = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, signed);
  if (!ok) return null;

  if (!payload.sub || !payload.email || !payload.name) return null;
  return { sub: payload.sub, email: payload.email, name: payload.name, picture: payload.picture };
}

// ─── Owned posts: publish (POSSE origin) + feed (syndication source) ─────────
//
// The strangle: you compose ONCE here. The canonical copy is committed to the
// content repo (git-as-database); the silos (Bluesky today, more later) get
// syndicated copies that link back to the canonical. /api/feed emits that
// owned store as RSS / JSON Feed — a first-class source anything can subscribe
// to, including other creators' HQs. The owned site is the origin; the big
// platforms become pipes.

interface Post {
  id: string;                    // `<ms-timestamp>-<8-char>` — sortable, unique
  text: string;
  title?: string;
  media?: string[];              // URLs, shown on the owned site
  author: { name: string; email: string; sub: string };  // sub = last 8 of Google sub
  createdAt: string;             // ISO
  canonicalUrl: string;          // the owned-site permalink (the origin)
  syndications: Array<{ platform: string; url: string }>;  // where copies landed
}

// Resolve a stream key to its repo — either an imprint allowlist key, or a
// roster creator's slug (their own registered repo). Roster resolution is what
// lets any registered creator publish to their own soil, not just the imprint.
async function resolveStream(key: string): Promise<{ owner: string; repo: string; creator: CreatorRecord | null } | null> {
  const allow = REPO_ALLOWLIST[key];
  if (allow) return { owner: allow.owner, repo: allow.repo, creator: null };
  const roster = await fetchRoster();
  const rec = roster?.find((c) => c.slug === key) ?? null;
  if (rec && typeof rec.repo === "string" && REPO_RE.test(rec.repo)) {
    const [owner, repo] = rec.repo.split("/");
    return { owner, repo, creator: rec };
  }
  return null;
}

async function publishPost(request: Request, env: Env): Promise<Response> {
  const payload = await parseJson(request);
  if (!payload) return jsonError(400, "invalid JSON body");
  const { googleIdToken, content, text, title, media, syndicate } = payload as {
    googleIdToken?: string; content?: string; text?: string; title?: string;
    media?: unknown; syndicate?: unknown;
  };
  if (typeof googleIdToken !== "string") return jsonError(400, "missing googleIdToken");
  if (typeof content !== "string" || content.length === 0) return jsonError(400, "missing content stream");
  if (typeof text !== "string" || text.trim().length === 0) return jsonError(400, "missing text");
  if (text.length > 10000) return jsonError(413, "post too long (max 10000)");

  const identity = await verifyGoogleToken(googleIdToken, env);
  if (!identity) return jsonError(401, "invalid or expired Google token");

  const stream = await resolveStream(content);
  if (!stream) return jsonError(400, `unknown content stream "${content}"`);
  // A roster creator may only post to their own registered stream; the imprint
  // allowlist streams stay open to the imprint's signed-in operators.
  if (stream.creator && stream.creator.registeredBy !== identity.email) {
    return jsonError(403, `"${content}" isn't yours to post to`);
  }
  const { owner, repo } = stream;
  const mediaUrls = Array.isArray(media)
    ? media.filter((m): m is string => typeof m === "string").slice(0, 8) : undefined;
  const targets = Array.isArray(syndicate)
    ? syndicate.filter((s): s is string => typeof s === "string") : [];

  const id = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
  const post: Post = {
    id,
    text: text.trim(),
    ...(typeof title === "string" && title.trim() ? { title: title.trim() } : {}),
    ...(mediaUrls && mediaUrls.length ? { media: mediaUrls } : {}),
    author: { name: identity.name, email: identity.email, sub: identity.sub.slice(-8) },
    createdAt: new Date().toISOString(),
    canonicalUrl: `${SITE_BASE}/${content}/posts/${id}`,
    syndications: [],
  };

  // Syndicate OUT first, so the canonical record captures where copies landed.
  const notes: string[] = [];
  if (targets.includes("bluesky")) {
    if (env.BLUESKY_HANDLE && env.BLUESKY_APP_PASSWORD) {
      try {
        const url = await publishToBluesky(env, post.text, post.canonicalUrl);
        if (url) post.syndications.push({ platform: "bluesky", url });
      } catch (e) {
        notes.push(`bluesky: ${e instanceof Error ? e.message : String(e)}`);
      }
    } else {
      notes.push("bluesky: not configured (set BLUESKY_HANDLE + BLUESKY_APP_PASSWORD secrets)");
    }
  }
  // RSS-out needs no push: the post is now the newest item at /api/feed?content=<content>.

  const committed = await commitPost(env, owner, repo, post, identity.email);
  if ("error" in committed) return jsonError(committed.status, committed.error);

  return jsonOk({ post, syndicated: post.syndications, feedUrl: `/api/feed?content=${content}`, notes });
}

// GET → prepend → PUT posts.json (git-as-database), same shape as registerCreator.
async function commitPost(
  env: Env, owner: string, repo: string, post: Post, actorEmail: string,
): Promise<{ ok: true } | { error: string; status: number }> {
  const contentsUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${POSTS_FILE_PATH}`;
  const getResp = await ghFetch(env, contentsUrl);
  let posts: Post[] = [];
  let sha: string | undefined;
  if (getResp.ok) {
    const file = await getResp.json() as { content: string; sha: string; encoding: string };
    sha = file.sha;
    if (file.encoding === "base64") {
      try { posts = JSON.parse(b64decodeUtf8(file.content)) as Post[]; } catch { posts = []; }
    }
  } else if (getResp.status !== 404) {
    return { error: `couldn't read ${POSTS_FILE_PATH}: HTTP ${getResp.status}`, status: 500 };
  }
  if (!Array.isArray(posts)) posts = [];
  posts.unshift(post);                             // newest first
  if (posts.length > 1000) posts = posts.slice(0, 1000);

  const body: Record<string, unknown> = {
    message: `post ${post.id}${post.title ? ` — ${post.title}` : ""}\n\nvia /api/publish by ${actorEmail}`,
    content: b64encodeUtf8(JSON.stringify(posts, null, 2) + "\n"),
  };
  if (sha) body.sha = sha;
  const putResp = await ghFetch(env, contentsUrl, { method: "PUT", body: JSON.stringify(body) });
  if (!putResp.ok) return { error: `commit failed: HTTP ${putResp.status}`, status: putResp.status };
  return { ok: true };
}

// Post to Bluesky via the AT Protocol. Teaser + canonical link (POSSE), with a
// facet so the link is clickable. Returns the bsky.app permalink.
async function publishToBluesky(env: Env, text: string, link: string): Promise<string | null> {
  const sess = await fetch("https://bsky.social/xrpc/com.atproto.server.createSession", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ identifier: env.BLUESKY_HANDLE, password: env.BLUESKY_APP_PASSWORD }),
  });
  if (!sess.ok) throw new Error(`createSession HTTP ${sess.status}`);
  const { accessJwt, did } = await sess.json() as { accessJwt: string; did: string };

  const teaser = text.length > 260 ? text.slice(0, 259) + "…" : text;
  const prefix = `${teaser}\n\n`;
  const postText = `${prefix}${link}`;
  const enc = new TextEncoder();
  const byteStart = enc.encode(prefix).length;
  const byteEnd = byteStart + enc.encode(link).length;
  const record = {
    $type: "app.bsky.feed.post",
    text: postText,
    createdAt: new Date().toISOString(),
    facets: [{
      index: { byteStart, byteEnd },
      features: [{ $type: "app.bsky.richtext.facet#link", uri: link }],
    }],
  };
  const create = await fetch("https://bsky.social/xrpc/com.atproto.repo.createRecord", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${accessJwt}` },
    body: JSON.stringify({ repo: did, collection: "app.bsky.feed.post", record }),
  });
  if (!create.ok) throw new Error(`createRecord HTTP ${create.status}`);
  const { uri } = await create.json() as { uri: string };
  const rkey = uri.split("/").pop();
  return rkey ? `https://bsky.app/profile/${env.BLUESKY_HANDLE}/post/${rkey}` : null;
}

// The POSSE origin feed. Reads the canonical posts store (raw = CDN-cached, no
// token) and emits RSS 2.0 (default) or JSON Feed 1.1.
async function getFeed(_env: Env, url: URL): Promise<Response> {
  const content = url.searchParams.get("content") ?? "";
  const format = (url.searchParams.get("format") ?? "rss").toLowerCase();
  const stream = await resolveStream(content);
  if (!stream) return jsonError(400, `unknown content stream "${content}"`);

  const rawUrl = `https://raw.githubusercontent.com/${stream.owner}/${stream.repo}/HEAD/${POSTS_FILE_PATH}`;
  const resp = await fetch(rawUrl);
  let posts: Post[] = [];
  if (resp.ok) { try { posts = await resp.json() as Post[]; } catch { posts = []; } }
  if (!Array.isArray(posts)) posts = [];

  const title = `${content} · Algorithmic Arts`;
  const home = `${SITE_BASE}/${content}`;
  if (format === "json") {
    return new Response(JSON.stringify(jsonFeed(title, home, url.href, posts), null, 2), {
      headers: { "Content-Type": "application/feed+json; charset=utf-8", "Cache-Control": "public, max-age=300" },
    });
  }
  return new Response(rssFeed(title, home, posts), {
    headers: { "Content-Type": "application/rss+xml; charset=utf-8", "Cache-Control": "public, max-age=300" },
  });
}

function rssFeed(title: string, link: string, posts: Post[]): string {
  const items = posts.map((p) => {
    const t = p.title ?? (p.text.length > 80 ? p.text.slice(0, 77) + "…" : p.text);
    const pub = new Date(p.createdAt).toUTCString();
    return `    <item>
      <title>${xmlEscape(t)}</title>
      <link>${xmlEscape(p.canonicalUrl)}</link>
      <guid isPermaLink="false">${xmlEscape(p.id)}</guid>
      <pubDate>${pub}</pubDate>
      <description>${xmlEscape(p.text)}</description>
    </item>`;
  }).join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
    <title>${xmlEscape(title)}</title>
    <link>${xmlEscape(link)}</link>
    <description>${xmlEscape(title)} — published on its own soil, syndicated everywhere.</description>
${items}
  </channel></rss>`;
}

function jsonFeed(title: string, homeUrl: string, feedUrl: string, posts: Post[]): unknown {
  return {
    version: "https://jsonfeed.org/version/1.1",
    title,
    home_page_url: homeUrl,
    feed_url: feedUrl,
    items: posts.map((p) => ({
      id: p.id,
      url: p.canonicalUrl,
      ...(p.title ? { title: p.title } : {}),
      content_text: p.text,
      date_published: p.createdAt,
      author: { name: p.author.name },
      ...(p.media && p.media.length ? { attachments: p.media.map((u) => ({ url: u, mime_type: "image/*" })) } : {}),
    })),
  };
}

function xmlEscape(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

function b64encodeUtf8(str: string): string {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function b64decodeUtf8(b64: string): string {
  const bin = atob(b64.replace(/\n/g, ""));
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

// ─── Helpers ────────────────────────────────────────────────────────────────

async function ghFetch(env: Env, url: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${env.GITHUB_TOKEN}`);
  headers.set("Accept", "application/vnd.github+json");
  headers.set("X-GitHub-Api-Version", "2022-11-28");
  headers.set("User-Agent", "algorithmic-arts-community-worker");
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  return fetch(url, { ...init, headers });
}

function attributedBody(identity: GoogleIdentity, body: string): string {
  // Attribution in the body header so it survives the bot identity.
  // The last 8 chars of Google's per-account `sub` are kept in a
  // trailer so we can match posts to authors later (edit / delete
  // paths in a future phase).
  const subHash = identity.sub.slice(-8);
  return `**${identity.name}**\n\n${body.trim()}\n\n<sub>posted via algorithmic-arts.binary-blender.com · sub:${subHash}</sub>`;
}

async function parseJson(request: Request): Promise<unknown | null> {
  try { return await request.json(); } catch { return null; }
}

async function passUpstreamError(resp: Response): Promise<Response> {
  const text = await resp.text();
  return jsonError(resp.status, `upstream ${resp.status}: ${text.slice(0, 500)}`);
}

function jsonOk(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function jsonError(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function preflight(request: Request): Response {
  const origin = request.headers.get("Origin");
  if (origin === null || !ALLOWED_ORIGINS.has(origin)) {
    return new Response("forbidden origin", { status: 403 });
  }
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin":  origin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept",
      "Access-Control-Max-Age":       "86400",
      "Vary":                         "Origin",
    },
  });
}

function withCors(response: Response, origin: string | null): Response {
  if (!origin) return response;
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Vary", "Origin");
  return new Response(response.body, { status: response.status, headers });
}
