// Vercel serverless function: extract design tokens from a public URL and
// generate a DESIGN.md. Defensive guards: http/https only, private/internal
// hosts blocked, manual redirect re-validation, timeouts, size caps.
// Note: DNS-rebinding is out of scope here; guards cover literal hostnames.

const MAX_HTML_BYTES = 2_000_000;
const MAX_CSS_BYTES_PER_FILE = 400_000;
const MAX_CSS_FILES = 4;
const MAX_TOTAL_CSS = 1_200_000;
const DOC_TIMEOUT_MS = 8000;
const CSS_TIMEOUT_MS = 5000;
const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36 DESIGNmdExtractor/1.0";

function httpError(status, code, message) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  return e;
}

function isBlockedHost(hostname) {
  const h = String(hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
  if (!h) return true;
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if (h === "::1" || h === "::" || h === "0.0.0.0") return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    if (a === 0 || a === 10 || a === 127 || a === 169 || a >= 224) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }
  if (h === "metadata.google.internal") return true;
  return false;
}

async function fetchWithGuards(target, timeoutMs) {
  let url = target;
  const maxRedirects = 4;
  for (let i = 0; i <= maxRedirects; i++) {
    let u;
    try {
      u = new URL(url);
    } catch (_) {
      throw httpError(400, "invalid-url", "That doesn't look like a valid URL.");
    }
    if (!/^https?:$/.test(u.protocol)) {
      throw httpError(400, "invalid-url", "Only http/https URLs are supported.");
    }
    if (isBlockedHost(u.hostname)) {
      throw httpError(400, "private-address", "Private and internal addresses aren't allowed for security reasons.");
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    let res;
    try {
      res = await fetch(u, {
        redirect: "manual",
        signal: ctrl.signal,
        headers: { "User-Agent": UA, Accept: "text/html,text/css,*/*;q=0.8" }
      });
    } catch (err) {
      clearTimeout(timer);
      if (err && err.name === "AbortError") {
        throw httpError(504, "timeout", "The site took too long to respond.");
      }
      throw httpError(502, "fetch-failed", "Couldn't reach that site. It may block bots or be offline.");
    }
    clearTimeout(timer);
    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const loc = res.headers.get("location");
      if (!loc) break;
      url = new URL(loc, u).href;
      continue;
    }
    return res;
  }
  throw httpError(508, "too-many-redirects", "That URL redirected too many times.");
}

function normalizeHex(hex) {
  let h = hex.toLowerCase();
  if (h.length === 4) {
    h = "#" + h[1] + h[1] + h[2] + h[2] + h[3] + h[3];
  }
  return h;
}

function looksLikeColor(v) {
  return /^#[0-9a-fA-F]{3,8}$/.test(v) || /^rgba?\(/i.test(v) || /^hsla?\(/i.test(v);
}

function countTop(map, n) {
  return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
}

function pxValue(token) {
  const m = String(token).match(/^([0-9]*\.?[0-9]+)(px|rem|em)$/i);
  if (!m) return null;
  const num = parseFloat(m[1]);
  const unit = m[2].toLowerCase();
  return unit === "px" ? num : num * 16;
}

function extractTokens(cssText) {
  const colors = new Map();
  const fonts = new Map();
  const sizes = new Map();
  const spacing = new Set();
  const radii = new Map();
  const shadows = new Map();
  const durations = new Set();

  const bump = (map, key) => map.set(key, (map.get(key) || 0) + 1);

  // Colors: hex, rgb(a), hsla() — all hues including white are part of a palette
  for (const m of cssText.matchAll(/#[0-9a-fA-F]{6}\b|#[0-9a-fA-F]{3}\b/g)) {
    bump(colors, normalizeHex(m[0]));
  }
  for (const m of cssText.matchAll(/rgba?\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*(?:,\s*[0-9.]+\s*)?\)/gi)) {
    bump(colors, m[0].replace(/\s+/g, "").toLowerCase());
  }
  for (const m of cssText.matchAll(/hsla?\(\s*\d{1,3}\s*,\s*[0-9.]+%\s*,\s*[0-9.]+%\s*(?:,\s*[0-9.]+\s*)?\)/gi)) {
    bump(colors, m[0].replace(/\s+/g, "").toLowerCase());
  }

  // Custom properties that hold colors or fonts (design tokens)
  for (const m of cssText.matchAll(/--[A-Za-z0-9-_]+\s*:\s*([^;{}]+)/g)) {
    const v = m[1].trim();
    if (looksLikeColor(v) && v.length <= 48) bump(colors, v.replace(/\s+/g, "").toLowerCase());
    if (/font/i.test(m[0]) && !looksLikeColor(v) && v.length <= 80) bump(fonts, v.replace(/["']/g, "").trim());
  }

  for (const m of cssText.matchAll(/font-family\s*:\s*([^;{}]+)/gi)) {
    const v = m[1].replace(/["']/g, "").trim();
    if (v && v.length <= 80) bump(fonts, v);
  }
  for (const m of cssText.matchAll(/font-size\s*:\s*([0-9]*\.?[0-9]+)(px|rem|em)\b/gi)) {
    const raw = m[1] + m[2].toLowerCase();
    const px = pxValue(raw);
    if (px != null && px >= 8 && px <= 96) sizes.set(raw, px);
  }
  for (const m of cssText.matchAll(/(?:padding|margin|gap|row-gap|column-gap)\s*:\s*([^;{}]+)/gi)) {
    for (const t of m[1].matchAll(/[0-9]*\.?[0-9]+(?:px|rem|em)\b/gi)) {
      const px = pxValue(t[0]);
      if (px != null && px > 0 && px <= 160) spacing.add(t[0].toLowerCase());
    }
  }
  for (const m of cssText.matchAll(/border-radius\s*:\s*([^;{}]+)/gi)) {
    const v = m[1].trim();
    if (v && v.length <= 60) bump(radii, v);
  }
  for (const m of cssText.matchAll(/box-shadow\s*:\s*([^;{}]+)/gi)) {
    const v = m[1].trim();
    if (v && v !== "none" && v.length <= 140) bump(shadows, v);
  }
  for (const m of cssText.matchAll(/(?:transition|animation)(?:-duration)?\s*:[^;{}]*?([0-9]*\.?[0-9]+m?s)\b/gi)) {
    durations.add(m[1].toLowerCase());
  }

  return { colors, fonts, sizes, spacing, radii, shadows, durations };
}

function formatPalette(colorMap) {
  const top = countTop(colorMap, 10);
  return top.map(([c, n]) => `${c} (${n}×)`).join(" · ");
}

function formatSizes(sizeMap) {
  return [...sizeMap.entries()]
    .sort((a, b) => a[1] - b[1])
    .slice(0, 8)
    .map(([raw]) => raw)
    .join(", ");
}

function buildDesignMd({ systemName, brand, url, description, tokens }) {
  const palette = formatPalette(tokens.colors) || "n/a";
  const fontList = countTop(tokens.fonts, 3).map(([f]) => f).join("; ") || "n/a";
  const sizes = formatSizes(tokens.sizes) || "n/a";
  const spacingVals = [...tokens.spacing]
    .map((raw) => ({ v: pxValue(raw), raw }))
    .sort((a, b) => a.v - b.v)
    .slice(0, 8)
    .map((x) => x.raw)
    .join(", ") || "n/a";
  const radii = countTop(tokens.radii, 5).map(([r]) => r).join(" · ") || "n/a";
  const shadows = countTop(tokens.shadows, 3).map(([s]) => s).join(" · ") || "n/a";
  const durations = [...tokens.durations].sort().slice(0, 5).join(", ") || "n/a";

  return `# ${systemName}

## Mission
Create implementation-ready, token-driven UI guidance for ${brand} that is optimized for consistency, accessibility, and fast delivery across the web.

## Brand
- Product/brand: ${brand}
- URL: ${url}
- Audience: website visitors and product users
- Product surface: web
- Page summary: ${description || "n/a"}
- Extraction method: server-side HTML/CSS fetch by design-md-chrome.vercel.app. For computed styles, hover states, and live token coverage, use the Chrome extension on the active tab.

## Style Foundations
- Visual style: inferred from extracted tokens
- Main font style: ${fontList}
- Typography scale: ${sizes}
- Color palette: ${palette}
- Spacing scale: ${spacingVals}
- Radius/shadow/motion tokens: radius ${radii} · shadow ${shadows} · motion ${durations}

## Accessibility
- Target: WCAG 2.2 AA
- Keyboard-first interactions required.
- Focus-visible rules required.
- Contrast constraints required.

## Writing Tone
Concise, confident, implementation-focused.

## Rules: Do
- Use semantic tokens, not raw hex values, in component guidance.
- Every component must define states for default, hover, focus-visible, active, disabled, loading, and error.
- Component behavior should specify responsive and edge-case handling.
- Interactive components must document keyboard, pointer, and touch behavior.
- Accessibility acceptance criteria must be testable in implementation.

## Rules: Don't
- Do not allow low-contrast text or hidden focus indicators.
- Do not introduce one-off spacing or typography exceptions.
- Do not use ambiguous labels or non-descriptive actions.

## Guideline Authoring Workflow
1. Restate design intent in one sentence.
2. Define foundations and tokens.
3. Define component anatomy, variants, and interactions.
4. Add accessibility acceptance criteria.
5. Add anti-patterns and migration notes.
6. End with QA checklist.

## Required Output Structure
- Context and goals
- Design tokens and foundations
- Component-level rules (anatomy, variants, states, responsive behavior)
- Accessibility requirements and testable acceptance criteria
- Content and tone standards with examples
- Anti-patterns and prohibited implementations
- QA checklist

## Component Rule Expectations
- Include keyboard, pointer, and touch behavior.
- Include spacing and typography token requirements.
- Include long-content, overflow, and empty-state handling.

## Quality Gates
- Every non-negotiable rule uses "must".
- Every recommendation uses "should".
- Every accessibility rule is testable in implementation.
- Prefer system consistency over local visual exceptions.
`;
}

function decodeEntities(s) {
  return String(s)
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

// Best-effort in-memory rate limit (per serverless instance): 10 req / 5 min / IP
const RATE_LIMIT = 10;
const RATE_WINDOW_MS = 5 * 60 * 1000;
const rateMap = new Map();
function isRateLimited(ip) {
  if (!ip) return false;
  const now = Date.now();
  let entry = rateMap.get(ip);
  if (!entry || now - entry.start > RATE_WINDOW_MS) {
    entry = { start: now, count: 0 };
    rateMap.set(ip, entry);
  }
  entry.count++;
  if (rateMap.size > 5000) rateMap.clear();
  return entry.count > RATE_LIMIT;
}

module.exports = async (req, res) => {
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  if (req.method !== "GET") {
    res.status(405).json({ ok: false, code: "method-not-allowed", error: "Use GET." });
    return;
  }
  const clientIp = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim()
    || req.headers["x-real-ip"]
    || (req.socket && req.socket.remoteAddress)
    || "";
  if (isRateLimited(clientIp)) {
    res.status(429).json({ ok: false, code: "rate-limited", error: "Too many requests — wait a few minutes and try again." });
    return;
  }

  let target;
  try {
    target = new URL(req.url, `http://${req.headers.host || "localhost"}`).searchParams.get("url");
  } catch (_) {
    target = null;
  }
  if (!target || !String(target).trim()) {
    res.status(400).json({ ok: false, code: "missing-url", error: "Provide ?url=https://example.com" });
    return;
  }

  let pageUrl;
  try {
    pageUrl = new URL(target.trim());
    if (!/^https?:$/.test(pageUrl.protocol)) throw new Error("protocol");
  } catch (_) {
    res.status(400).json({ ok: false, code: "invalid-url", error: "That doesn't look like a valid URL — try https://example.com" });
    return;
  }
  if (isBlockedHost(pageUrl.hostname)) {
    res.status(400).json({ ok: false, code: "private-address", error: "Private and internal addresses aren't allowed for security reasons." });
    return;
  }

  try {
    const res2 = await fetchWithGuards(pageUrl.href, DOC_TIMEOUT_MS);
    const ctype = String(res2.headers.get("content-type") || "");
    const declaredLen = parseInt(res2.headers.get("content-length") || "0", 10);
    if (declaredLen > MAX_HTML_BYTES) {
      throw httpError(413, "too-large", "That page is too large to process.");
    }
    if (ctype && !/text\/html|application\/xhtml/i.test(ctype)) {
      throw httpError(415, "not-html", "That URL didn't return an HTML page.");
    }
    let html = await res2.text();
    if (html.length > MAX_HTML_BYTES) html = html.slice(0, MAX_HTML_BYTES);

    const finalUrl = res2.url || pageUrl.href;
    const host = new URL(finalUrl).hostname.replace(/^www\./, "");

    const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    const rawTitle = titleMatch ? decodeEntities(titleMatch[1]).trim() : "";
    const descMatch = html.match(/<meta[^>]+name=["']description["'][^>]*content=["']([^"']*)["']/i)
      || html.match(/<meta[^>]+content=["']([^"']*)["'][^>]*name=["']description["']/i);
    const description = descMatch ? decodeEntities(descMatch[1]).trim().slice(0, 200) : "";
    const siteNameMatch = html.match(/<meta[^>]+property=["']og:site_name["'][^>]*content=["']([^"']*)["']/i);
    const siteName = siteNameMatch ? decodeEntities(siteNameMatch[1]).trim() : "";

    const systemName =
      siteName
      || (rawTitle ? rawTitle.split(/\s*[|·—–-]\s/)[0].trim() : "")
      || host;

    // Gather CSS: inline <style> blocks, style="" attributes, linked stylesheets
    let cssText = "";
    for (const m of html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/gi)) {
      cssText += "\n" + m[1];
    }
    for (const m of html.matchAll(/style\s*=\s*"([^"]*)"/gi)) {
      cssText += "\n" + m[1];
    }
    cssText = cssText.slice(0, MAX_TOTAL_CSS);

    const linkTags = [...html.matchAll(/<link[^>]+>/gi)]
      .map((m) => m[0])
      .filter((tag) => /rel\s*=\s*["']?stylesheet/i.test(tag))
      .map((tag) => {
        const h = tag.match(/href\s*=\s*["']([^"']+)["']/i);
        return h ? h[1] : null;
      })
      .filter(Boolean)
      .slice(0, MAX_CSS_FILES);

    const cssFetches = linkTags.map(async (href) => {
      try {
        const cssUrl = new URL(href, finalUrl).href;
        if (!/^https?:/i.test(cssUrl)) return "";
        if (isBlockedHost(new URL(cssUrl).hostname)) return "";
        const cssRes = await fetchWithGuards(cssUrl, CSS_TIMEOUT_MS);
        const cssCtype = String(cssRes.headers.get("content-type") || "");
        if (cssCtype && !/text\/css|text\/plain/i.test(cssCtype)) return "";
        let text = await cssRes.text();
        return text.slice(0, MAX_CSS_BYTES_PER_FILE);
      } catch (_) {
        return "";
      }
    });
    const cssParts = await Promise.all(cssFetches);
    cssText = (cssText + "\n" + cssParts.join("\n")).slice(0, MAX_TOTAL_CSS);

    const tokens = extractTokens(cssText);
    if (tokens.colors.size === 0 && tokens.fonts.size === 0) {
      throw httpError(422, "no-tokens", "Fetched the page but couldn't find usable styles. Try another URL or use the Chrome extension.");
    }

    const markdown = buildDesignMd({
      systemName,
      brand: systemName,
      url: finalUrl,
      description,
      tokens
    });

    res.status(200).json({
      ok: true,
      title: rawTitle || systemName,
      hostname: host,
      stats: {
        colors: tokens.colors.size,
        fonts: tokens.fonts.size,
        fontSizes: tokens.sizes.size,
        spacing: tokens.spacing.size,
        radii: tokens.radii.size,
        shadows: tokens.shadows.size,
        durations: tokens.durations.size
      },
      markdown
    });
  } catch (err) {
    const status = err && err.status ? err.status : 500;
    const code = err && err.code ? err.code : "internal-error";
    const message = err && err.code ? err.message : "Extraction failed unexpectedly.";
    res.status(status).json({ ok: false, code, error: message });
  }
};
