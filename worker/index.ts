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
}

const COMMENTS_PREFIX = "/api/comments";
const LIKES_PREFIX    = "/api/likes";
const REGISTER_PREFIX = "/api/register";

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
    if (!isComments && !isLikes && !isRegister) {
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
  return jsonError(404, `no route: ${request.method} ${url.pathname}`);
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
