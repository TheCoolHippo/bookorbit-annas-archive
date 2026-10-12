/**
 * Anna's Archive as a BookOrbit indexer plugin, with Library Genesis as its fallback catalogue.
 *
 * One file, no dependencies, no BookOrbit imports. Everything it needs from the host arrives in
 * `host`, which is also what applies the address policy, the request deadline and the log
 * sanitising this file is not trusted to apply itself.
 *
 * Why two catalogues. Anna's Archive serves its search pages behind DDoS-Guard on every mirror. A
 * plain fetch gets a JavaScript challenge, and some networks get a manual CAPTCHA that nothing
 * automated can answer. Its JSON endpoints under `/dyn/` are not gated. So a search tries Anna's
 * Archive first, optionally through a FlareSolverr instance, and when the protection holds it
 * searches Library Genesis instead. Both catalogues name a file by the same md5, so a release
 * found on either one resolves the same way.
 *
 * Downloads never touch the protected pages: an account key with a membership uses Anna's
 * Archive's fast download API, and everything else goes through the Library Genesis download
 * service, by md5.
 *
 * The Library Genesis parsing is adapted from the `libgen` plugin in
 * orbit-plugins/bookorbit-plugins-extra (MIT). The challenge detection follows calibrain/shelfmark
 * (MIT), which met every failure mode below first.
 */


const DEFAULT_MIRRORS = 'https://annas-archive.gl,https://annas-archive.pk,https://annas-archive.gd';
const DEFAULT_LIBGEN_MIRRORS = 'https://libgen.li,https://libgen.bz';
const LIBGEN_DOWNLOAD_ORIGIN = 'https://libgen.download';

const DEFAULT_EBOOK_FORMATS = 'epub,mobi,azw3,fb2';
const ALLOWED_FORMATS = ['epub', 'mobi', 'azw', 'azw3', 'fb2', 'djvu', 'pdf'];

/** A full result page of markup, with room to spare. Nothing is buffered past this. */
const MAX_PAGE_BYTES = 4 * 1024 * 1024;
const MAX_JSON_BYTES = 64 * 1024;
const MAX_REFUSAL_BYTES = 8 * 1024;
const MAX_REFUSAL_CHARS = 200;

/**
 * The self-imposed ceiling on a whole search, under the 20 seconds BookOrbit gives one indexer.
 * Being cut off by the host loses every row already collected; stopping here returns them.
 */
const SEARCH_BUDGET_MS = 17_000;
/** What a Library Genesis page needs, measured at 3 to 8 seconds; kept free for the fallback. */
const LIBGEN_RESERVE_MS = 7_000;
/** Below this, a FlareSolverr solve is not worth starting: they take 5 to 30 seconds. */
const MIN_SOLVE_MS = 4_000;

/**
 * How long a search skips Anna's Archive after its protection held. Every mirror shares the same
 * protection, so asking again on the next search only spends a second of the budget to learn the
 * same thing. Module state, so it lasts as long as the BookOrbit process and no longer.
 */
const BLOCKED_COOLDOWN_MS = 15 * 60 * 1000;
const blockedUntil = new Map();

const DRIFT_REASON = "Anna's Archive answered with a search page this plugin cannot read; its layout may have changed";

/**
 * What a browser looks like, because Node's own fetch does not. Politeness, not evasion: no header
 * here gets past DDoS-Guard, which fingerprints far more than a user agent.
 */
const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36';
const HTML_ACCEPT = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
const ACCEPT_LANGUAGE = 'en-US,en;q=0.9';

/* ----------------------------------------------------------------------------------------------
 * Protection pages
 * ------------------------------------------------------------------------------------------- */

/**
 * Markers of an interstitial, matched lowercase. A protected site links its own DDoS-Guard
 * endpoints on every real page too, so these only count on a page small enough to be an
 * interstitial: a few kilobytes, against the hundreds a results page weighs.
 */
const CHALLENGE_MARKERS = [
  '<title>ddos-guard</title>',
  '/.well-known/ddos-guard/',
  'checking your browser before accessing',
  'could not verify your browser automatically',
  'complete the manual check to continue',
  'just a moment',
  '/cdn-cgi/challenge-platform',
];
const MAX_CHALLENGE_CHARS = 64 * 1024;

/** Paths that only exist on the real site. A parked domain's page has none of them. */
const ANNAS_PAGE_MARKERS = ['/md5/', 'aarecord', '/dyn/', '/datasets', '/fast_download', '/slow_download'];

/**
 * Checked after the site's own markers, as Shelfmark learned to (#1289): a real Anna's Archive
 * page carries a `DDOS-GUARD` comment in its inline script, and a genuine interstitial carries
 * nothing of Anna's Archive at all.
 */
function challengeMarker(html) {
  if (!html || html.length > MAX_CHALLENGE_CHARS || looksLikeAnnasArchive(html)) return null;
  const lowered = html.toLowerCase();
  return CHALLENGE_MARKERS.find((marker) => lowered.includes(marker)) ?? null;
}

/** The one marker worth naming apart: a manual CAPTCHA is waited out, not configured around. */
function isManualCaptcha(html) {
  const lowered = (html ?? '').toLowerCase();
  return lowered.includes('could not verify your browser automatically') || lowered.includes('complete the manual check');
}

function looksLikeAnnasArchive(html) {
  const lowered = html.toLowerCase();
  return ANNAS_PAGE_MARKERS.some((marker) => lowered.includes(marker));
}

/* ----------------------------------------------------------------------------------------------
 * The plugin
 * ------------------------------------------------------------------------------------------- */

export default {
  apiVersion: 1,
  version: '1.1.0',
  update: {
    manifestUrl: 'https://raw.githubusercontent.com/TheCoolHippo/bookorbit-annas-archive/main/updates/annas-archive.json',
    ed25519PublicKey: 'OlmPIog8s2G128FNUXGEIWoAsok_yUqQvHFK9T_1L-M',
  },
  type: 'annas-archive',
  label: "Anna's Archive",
  /**
   * Optional. Without a key everything still works through Library Genesis; with a member's key,
   * downloads use Anna's Archive's own fast servers first.
   */
  requiresCredential: false,
  credentialKind: 'apiKey',
  mediaKinds: ['ebook'],
  supportsIsbnSearch: true,
  usesCategories: false,
  /** Nothing is seeded back, so a seed goal here would be a number that means nothing. */
  seedsBack: false,
  defaultBaseUrl: 'https://annas-archive.gl',
  baseUrlHint:
    "The Anna's Archive mirror to try first. The account key is optional: a member's secret key enables fast downloads.",
  settingsFields: [
    {
      key: 'extraMirrors',
      type: 'string',
      label: 'Fallback mirrors',
      hint: "Other Anna's Archive addresses, tried in order when the main one is down or parked.",
      default: DEFAULT_MIRRORS,
      format: 'list',
    },
    {
      key: 'flareSolverrUrl',
      type: 'string',
      label: 'FlareSolverr URL',
      hint:
        "Optional, e.g. http://192.168.0.10:8191. Used to pass the DDoS-Guard check on search pages. A LAN address also needs 'allow private addresses' on this indexer.",
      default: '',
    },
    {
      key: 'libgenFallback',
      type: 'boolean',
      label: 'Search Library Genesis when blocked',
      hint: "Anna's Archive often answers with a check page no script can pass. Library Genesis holds most of the same files.",
      default: true,
    },
    {
      key: 'libgenMirrors',
      type: 'string',
      label: 'Library Genesis mirrors',
      hint: 'Tried in order. Mirrors carry the same catalogue but differ in speed and uptime.',
      default: DEFAULT_LIBGEN_MIRRORS,
      format: 'list',
    },
    {
      key: 'languages',
      type: 'string',
      label: 'Accepted languages',
      hint: 'ISO codes such as en, fr. Results stated in another language are dropped; results that state no language are kept. Empty accepts every language.',
      default: '',
      format: 'list',
    },
    {
      key: 'ebookFormats',
      type: 'string',
      label: 'Ebook formats',
      hint: 'Results in other formats are dropped.',
      default: DEFAULT_EBOOK_FORMATS,
      format: 'list',
      options: ALLOWED_FORMATS,
      minItems: 1,
    },
  ],

  async search(query, config, host, signal) {
    if (query.mediaKind !== 'ebook') {
      throw host.fail('unsupportedMedium', `Anna's Archive is searched for ebooks only, not ${query.mediaKind}s`);
    }
    const formats = configuredFormats(config);
    const started = Date.now();
    const remaining = () => SEARCH_BUDGET_MS - (Date.now() - started);

    const annas = await searchAnnas(query, config, formats, host, signal, remaining);
    if (annas.answered) {
      logSearch(host, config, query, 'annas', annas.releases.length, started);
      return annas.releases;
    }

    if (!libgenEnabled(config)) {
      throw host.fail('unreachable', annas.reason);
    }
    if (signal?.aborted) return [];

    host.logger.log(`[annas-archive.search] [fallback] indexerId=${config.id} reason="${annas.reason}" - searching Library Genesis`);
    try {
      const releases = await searchLibgen(query, config, formats, host, signal, remaining);
      logSearch(host, config, query, 'libgen', releases.length, started);
      return releases;
    } catch (error) {
      // Both catalogues failed. The Anna's Archive reason is usually the more useful one to read,
      // so it leads, and the Library Genesis error follows it.
      const detail = error instanceof Error ? error.message : String(error);
      throw host.fail('unreachable', `${annas.reason}; Library Genesis also failed: ${detail}`);
    }
  },

  async test(config, host) {
    const notes = [];
    try {
      const formats = configuredFormats(config);
      const probe = { title: 'dune', author: 'frank herbert', isbn13: null, isbn13s: [], mediaKind: 'ebook', language: null, limit: 5 };
      const started = Date.now();
      const remaining = () => SEARCH_BUDGET_MS - (Date.now() - started);

      // A test asks the protected site fresh, whatever an earlier search concluded.
      for (const mirror of mirrorsOf(config)) blockedUntil.delete(mirror);
      const annas = await searchAnnas(probe, config, formats, host, undefined, remaining);

      let searchVia;
      if (annas.answered) {
        searchVia = "Anna's Archive";
      } else if (libgenEnabled(config)) {
        await searchLibgen(probe, config, formats, host, undefined, () => SEARCH_BUDGET_MS);
        searchVia = 'Library Genesis';
        notes.push(annas.reason);
      } else {
        return { success: false, error: annas.reason };
      }

      if (config.credential) {
        const key = await checkKey(config, host);
        if (key === 'invalid') return { success: false, error: "Anna's Archive rejected the account key" };
        notes.push(key === 'member' ? 'fast downloads enabled' : `account key: ${key}`);
      }

      const suffix = notes.length ? ` (${notes.join('; ')})` : '';
      return { success: true, indexerName: `Anna's Archive, searching ${searchVia}${suffix}` };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      host.logger.warn(`[annas-archive.test] [fail] indexerId=${config.id} error="${message}" - test failed`);
      return { success: false, error: message };
    }
  },

  /** Resolved only after an approver picks a release. */
  async resolveFile(release, config, host, signal) {
    const md5 = md5Of(release);
    if (!md5) throw host.fail('error', 'that release carries no md5, so there is nothing to look up');

    if (config.credential) {
      const fast = await fastDownloadUrl(md5, config, host, signal);
      if (fast) {
        host.logger.log(`[annas-archive.resolve] [end] indexerId=${config.id} md5=${md5} via=fast - download link resolved`);
        return toFile(fast, release, host);
      }
    }

    const libgen = await libgenDownloadUrl(md5, config, host, signal);
    host.logger.log(`[annas-archive.resolve] [end] indexerId=${config.id} md5=${md5} via=${hostOf(libgen)} - download link resolved`);
    return toFile(libgen, release, host);
  },
};

/* ----------------------------------------------------------------------------------------------
 * Anna's Archive search
 * ------------------------------------------------------------------------------------------- */

/**
 * Searches Anna's Archive, and says whether it answered at all.
 *
 * `answered: false` is not "nothing found": it means the site could not be read, and `reason`
 * says why in words an administrator can act on. A real empty answer is `answered: true` with
 * no releases, and is not a reason to ask another catalogue.
 */
async function searchAnnas(query, config, formats, host, signal, remaining) {
  const mirrors = mirrorsOf(config);
  const now = Date.now();
  const open = mirrors.filter((mirror) => (blockedUntil.get(mirror)?.until ?? 0) <= now);
  if (open.length === 0) {
    const last = blockedUntil.get(mirrors[0])?.reason ?? "Anna's Archive answered with a protection check";
    return { answered: false, reason: `${last} (not asked again for a few minutes)` };
  }

  let reason = "no Anna's Archive mirror answered";
  let challenged = null;

  for (const mirror of open) {
    if (signal?.aborted || remaining() < LIBGEN_RESERVE_MS) break;
    const url = annasSearchUrl(mirror, query, formats, acceptedLanguages(config));

    let page;
    try {
      page = await readAnnasPage(host, url, config);
    } catch (error) {
      reason = `${hostOf(mirror)} failed: ${error instanceof Error ? error.message : String(error)}`;
      continue;
    }

    if (page.challenged) {
      // Every mirror shares the protection, so another mirror would only collect the same page.
      challenged = { mirror, url, captcha: page.captcha };
      break;
    }
    const parsed = parseAnnasPage(page.html, query, formats, acceptedLanguages(config));
    if (parsed === LAYOUT_DRIFT) return { answered: false, reason: DRIFT_REASON };
    if (parsed) return { answered: true, releases: parsed.slice(0, query.limit) };
    reason = `${hostOf(mirror)} did not answer with an Anna's Archive page (parked or seized domain?)`;
  }

  if (!challenged) return { answered: false, reason };

  const solver = solverUrl(config);
  if (solver && !challenged.captcha && remaining() - LIBGEN_RESERVE_MS >= MIN_SOLVE_MS) {
    try {
      const html = await solveWithFlareSolverr(host, solver, challenged.url, remaining() - LIBGEN_RESERVE_MS);
      const marker = challengeMarker(html);
      if (!marker) {
        const parsed = parseAnnasPage(html, query, formats, acceptedLanguages(config));
        if (parsed === LAYOUT_DRIFT) return { answered: false, reason: DRIFT_REASON };
        if (parsed) return { answered: true, releases: parsed.slice(0, query.limit) };
        return { answered: false, reason: "FlareSolverr returned a page that is not an Anna's Archive search page" };
      }
      // FlareSolverr reports "Challenge solved!" even when what it brings back is the next wall.
      challenged.captcha = isManualCaptcha(html);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      const reason = `FlareSolverr could not pass DDoS-Guard: ${detail}`;
      block(mirrors, reason);
      return { answered: false, reason };
    }
  }

  const blockedReason = challenged.captcha
    ? "Anna's Archive is serving DDoS-Guard's manual CAPTCHA to this network, which no automated client can answer"
    : solver
      ? "Anna's Archive's DDoS-Guard check was not passed in time"
      : "Anna's Archive answered with a DDoS-Guard check; set a FlareSolverr URL to pass it";
  block(mirrors, blockedReason);
  return { answered: false, reason: blockedReason };
}

function block(mirrors, reason) {
  const until = Date.now() + BLOCKED_COOLDOWN_MS;
  for (const mirror of mirrors) blockedUntil.set(mirror, { until, reason });
}

/**
 * The table view, because it lays every result out in fixed columns. The same parameters
 * Shelfmark sends: only records with a downloadable file, in the wanted formats.
 */
function annasSearchUrl(mirror, query, formats, accepted = []) {
  const url = new URL('/search', mirror);
  url.searchParams.set('index', '');
  url.searchParams.set('page', '1');
  url.searchParams.set('display', 'table');
  url.searchParams.append('acc', 'aa_download');
  url.searchParams.append('acc', 'external_download');
  for (const format of formats) url.searchParams.append('ext', format);

  const isbn = /^\d{13}$/.test(query.isbn13 ?? '') ? query.isbn13 : null;
  url.searchParams.set('q', isbn ?? '');
  if (!isbn) {
    let index = 1;
    if (query.title) {
      url.searchParams.set(`termtype_${index}`, 'title');
      url.searchParams.set(`termval_${index}`, stripParentheticals(query.title));
      index += 1;
    }
    if (query.author) {
      url.searchParams.set(`termtype_${index}`, 'author');
      url.searchParams.set(`termval_${index}`, query.author);
    }
  }
  const language = query.language ? normalizeLanguage(query.language) : null;
  if (language) url.searchParams.set('lang', language);
  else for (const code of accepted) url.searchParams.append('lang', code);
  return url.href;
}

/**
 * Fetches without following redirects, because DDoS-Guard's first move is a 302 to the same page
 * with `check=1`, and following it only lands on the 403 interstitial.
 */
async function readAnnasPage(host, url, config) {
  const response = await host.fetch(url, {
    method: 'GET',
    redirect: 'manual',
    headers: { 'User-Agent': USER_AGENT, Accept: HTML_ACCEPT, 'Accept-Language': ACCEPT_LANGUAGE },
  });

  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get('location') ?? '';
    await discard(response);
    if (/[?&]check=1/.test(location) || isDdosGuard(response)) return { challenged: true, captcha: false };
    throw host.fail('unreachable', `redirected to ${location || 'nowhere'}`);
  }
  if (response.status === 429) throw host.fail('throttled', "Anna's Archive is rate limiting us");

  const html = await readBoundedText(response, MAX_PAGE_BYTES);
  const marker = challengeMarker(html);
  if (marker) return { challenged: true, captcha: isManualCaptcha(html) };
  if (!response.ok) throw host.fail('error', `answered ${response.status}${refusalOf(html)}`);
  host.logger.log(`[annas-archive.fetch] [end] indexerId=${config.id} host=${hostOf(url)} bytes=${html.length} - page read`);
  return { challenged: false, html };
}

function isDdosGuard(response) {
  return (response.headers.get('server') ?? '').toLowerCase().includes('ddos-guard');
}

async function solveWithFlareSolverr(host, solver, url, budgetMs) {
  const response = await host.fetch(`${solver}/v1`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cmd: 'request.get', url, maxTimeout: Math.max(MIN_SOLVE_MS, Math.floor(budgetMs)) }),
  });
  const text = await readBoundedText(response, MAX_PAGE_BYTES);
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`FlareSolverr answered ${response.status} with something that is not JSON`);
  }
  if (body?.status !== 'ok') throw new Error(String(body?.message ?? `status ${body?.status ?? response.status}`).slice(0, MAX_REFUSAL_CHARS));
  return String(body.solution?.response ?? '');
}

/** Anna's Archive answered, but not in a shape this file reads. Not the same as nothing found. */
const LAYOUT_DRIFT = Symbol('layout drift');

/**
 * Releases from a search page; `LAYOUT_DRIFT` when it is Anna's Archive in an unreadable layout;
 * null when the page is not Anna's Archive at all.
 *
 * A page with no results table can be a genuine empty answer, a parked domain squatting on an old
 * mirror name, or the layout having changed. Only the first is a reason to report nothing found.
 */
function parseAnnasPage(page, query, formats, accepted = []) {
  // Comments first: a commented-out `<table>` would otherwise be read as the results.
  const html = page.replace(/<!--[\s\S]*?-->/g, '');
  const table = findFirstTable(html);
  if (!table) {
    if (/No files found\./i.test(html)) return [];
    return looksLikeAnnasArchive(html) ? LAYOUT_DRIFT : null;
  }

  const releases = [];
  const seen = new Set();
  for (const row of rowsOf(table)) {
    const release = annasRelease(row, formats);
    if (!release || seen.has(release.guid)) continue;
    if (!languagesAgree(query.language, release.language) || !languageAccepted(accepted, release.language)) continue;
    seen.add(release.guid);
    releases.push(release);
  }
  return releases;
}

/**
 * One row of the table view. Positional, like Shelfmark's reader of the same page: cover, title,
 * author, publisher, year, two unused, language, content type, format, size.
 */
const AA_MIN_CELLS = 11;
const AA = { title: 1, author: 2, publisher: 3, year: 4, language: 7, content: 8, format: 9, size: 10 };

function annasRelease(row, formats) {
  if (/^\s*your ad here/i.test(stripTags(row))) return null;
  const cells = cellsOf(row);
  if (cells.length < AA_MIN_CELLS) return null;

  const md5 = /\/md5\/([a-f0-9]{32})/i.exec(row)?.[1]?.toLowerCase();
  if (!md5) return null;

  const title = firstSpanOwnText(cells[AA.title]);
  const format = firstSpanText(cells[AA.format]).toLowerCase();
  if (!title || !format || !formats.includes(format)) return null;
  // Catalogue descriptors that some imported records carry in place of a title.
  if (title.includes('/') && title.length < 40 && !/\d/.test(title)) return null;

  const author = cleanAuthor(firstSpanText(cells[AA.author]));
  const language = languageCode(firstSpanText(cells[AA.language]));
  const year = firstSpanText(cells[AA.year]);

  return {
    guid: md5,
    ...readTitle(title),
    sizeBytes: parseSize(firstSpanText(cells[AA.size])),
    seeders: null,
    leechers: null,
    format,
    ...(language ? { language } : {}),
    ...(author ? { author } : {}),
    ...(/^\d{4}$/.test(year) ? { publishedAt: `${year}-01-01T00:00:00.000Z` } : {}),
    primaryFileCount: 1,
    fileCount: 1,
  };
}

/* ----------------------------------------------------------------------------------------------
 * Fast downloads (members)
 * ------------------------------------------------------------------------------------------- */

/**
 * A member's fast download link, or null when there is none to have. The API lives under `/dyn/`,
 * which DDoS-Guard does not gate, so this works on networks that only ever see the CAPTCHA.
 */
async function fastDownloadUrl(md5, config, host, signal) {
  for (const mirror of mirrorsOf(config)) {
    if (signal?.aborted) return null;
    let body;
    try {
      body = await readFastDownload(host, mirror, md5, config.credential);
    } catch {
      continue;
    }
    if (body?.download_url) return String(body.download_url);
    const error = String(body?.error ?? '');
    if (/invalid secret key/i.test(error)) throw host.fail('unauthorized', "Anna's Archive rejected the account key");
    // Out of fast downloads for the day, not a member, or the file is not on the fast servers:
    // Library Genesis is the next door, and the caller goes there.
    host.logger.warn(`[annas-archive.resolve] [skip] indexerId=${config.id} md5=${md5} reason="${error.slice(0, 120)}" - no fast download`);
    return null;
  }
  return null;
}

async function readFastDownload(host, mirror, md5, key) {
  const url = new URL('/dyn/api/fast_download.json', mirror);
  url.searchParams.set('md5', md5);
  url.searchParams.set('key', key);
  const response = await host.fetch(url.href, { method: 'GET', headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' } });
  const text = await readBoundedText(response, MAX_JSON_BYTES);
  return JSON.parse(text);
}

/**
 * Whether the stored key works. Asked about a file that certainly exists, so the only errors left
 * are about the key or the account.
 */
async function checkKey(config, host) {
  const probe = '805290ae7791f6fa5fabf9128f12e632';
  for (const mirror of mirrorsOf(config)) {
    let body;
    try {
      body = await readFastDownload(host, mirror, probe, config.credential);
    } catch {
      continue;
    }
    if (body?.download_url) return 'member';
    const error = String(body?.error ?? 'no answer');
    if (/invalid secret key/i.test(error)) return 'invalid';
    return error.slice(0, 80);
  }
  return "could not be checked: no mirror answered the API";
}

/* ----------------------------------------------------------------------------------------------
 * Library Genesis downloads
 * ------------------------------------------------------------------------------------------- */

const LIBGEN_GET_LINK = /href=["']((?:https?:\/\/[^"'\/]+)?\/?get\.php\?md5=[a-f0-9]{32}&(?:amp;)?key=[A-Za-z0-9]+)["']/i;

/**
 * A link the download client can fetch for this md5.
 *
 * The download service serves most files itself, and is the one link that needs no page read. For
 * the rest it answers with a redirect to a mirror's ad page, and the mirror it picks is not always
 * one that still exists: `libgen.vg` stopped resolving while the service kept sending people
 * there. So the service is asked without following redirects, and anything but the file itself
 * sends the search to the configured mirrors' own ad pages, which carry the real `get.php` link.
 */
async function libgenDownloadUrl(md5, config, host, signal) {
  const direct = new URL('/api/download', LIBGEN_DOWNLOAD_ORIGIN);
  direct.searchParams.set('id', md5);
  try {
    const response = await host.fetch(direct.href, { method: 'GET', redirect: 'manual', headers: { 'User-Agent': USER_AGENT } });
    await discard(response);
    if (response.ok) return direct.href;
  } catch {
    // Unreachable or refused: the mirrors below are the next door either way.
  }

  const failures = [];
  for (const mirror of libgenMirrorsOf(config)) {
    if (signal?.aborted) break;
    const page = new URL('/ads.php', mirror);
    page.searchParams.set('md5', md5);
    try {
      const response = await host.fetch(page.href, { method: 'GET', headers: { 'User-Agent': USER_AGENT, Accept: HTML_ACCEPT } });
      const html = await readBoundedText(response, MAX_PAGE_BYTES);
      const link = LIBGEN_GET_LINK.exec(html)?.[1];
      if (link) return new URL(link.replace(/&amp;/g, '&'), `${mirror}/`).href;
      failures.push(`${hostOf(mirror)}: ${response.ok ? 'no download link on the page' : `answered ${response.status}${refusalOf(html)}`}`);
    } catch (error) {
      failures.push(`${hostOf(mirror)}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  throw host.fail('unreachable', `no Library Genesis mirror offered this file (${failures.join('; ') || 'no mirror configured'})`);
}

/* ----------------------------------------------------------------------------------------------
 * Library Genesis search (adapted from orbit-plugins/bookorbit-plugins-extra, MIT)
 * ------------------------------------------------------------------------------------------- */

const LIBGEN_RESULTS_TABLE_ID = 'tablelibgen';
const LIBGEN_FILES_TAB = /curtab=f["'][^>]*>\s*Files\s*<span[^>]*>\s*\d+\s*<\/span>/i;
const LIBGEN_MIN_CELLS = 9;
const LG = { title: 0, author: 1, year: 3, language: 4, size: 6, format: 7 };
const LIBGEN_PAGE_SIZE = 50;
const LIBGEN_MD5_IN_HREF = /(?:ads|get)\.php\?md5=([a-f0-9]{32})/i;
const LIBGEN_ROW_ISBNS = /<font[^>]*color=["']green["'][^>]*>([^<]*)<\/font>/i;

/**
 * The ISBN first when the request states one, then title and author. One page each: this is the
 * fallback, and it shares one budget with an Anna's Archive attempt that already spent some of it.
 */
async function searchLibgen(query, config, formats, host, signal, remaining) {
  const passes = [];
  if (/^\d{13}$/.test(query.isbn13 ?? '')) passes.push({ req: query.isbn13, columns: ['i'] });
  passes.push({ req: host.buildSearchText(query), columns: ['t', 'a'] });

  const releases = [];
  const seen = new Set();
  const accepted = acceptedLanguages(config);
  let failure = null;

  for (const pass of passes) {
    if (releases.length >= query.limit || signal?.aborted || remaining() <= 0) break;
    try {
      const html = await readLibgenPage(host, config, pass);
      for (const release of libgenReleases(html, formats)) {
        if (seen.has(release.guid) || !languagesAgree(query.language, release.language)) continue;
        if (!languageAccepted(accepted, release.language)) continue;
        seen.add(release.guid);
        releases.push(release);
        if (releases.length >= query.limit) break;
      }
    } catch (error) {
      // An ISBN pass that errors is recovered by the text pass; rows in hand outlive a text pass
      // that errors after them. Only a search that found nothing at all has failed.
      failure ??= error;
    }
  }
  if (failure && releases.length === 0) throw failure;
  return releases;
}

/** Tries each mirror in turn: they share a catalogue and fail independently. */
async function readLibgenPage(host, config, pass) {
  const failures = [];
  for (const mirror of libgenMirrorsOf(config)) {
    const url = new URL('/index.php', mirror);
    url.searchParams.set('req', pass.req);
    url.searchParams.append('objects[]', 'f');
    url.searchParams.append('topics[]', 'l');
    url.searchParams.append('topics[]', 'f');
    for (const column of pass.columns) url.searchParams.append('columns[]', column);
    url.searchParams.set('res', String(LIBGEN_PAGE_SIZE));
    try {
      const response = await host.fetch(url.href, {
        method: 'GET',
        headers: { 'User-Agent': USER_AGENT, Accept: HTML_ACCEPT, 'Accept-Language': ACCEPT_LANGUAGE },
      });
      if (response.status === 429) throw host.fail('throttled', `${hostOf(mirror)} is rate limiting us`);
      const html = await readBoundedText(response, MAX_PAGE_BYTES);
      if (!response.ok) throw host.fail('error', `${hostOf(mirror)} answered ${response.status}${refusalOf(html)}`);
      // The catalogue's database refusing connections still answers 200, with one sentence.
      if (!findTable(html, LIBGEN_RESULTS_TABLE_ID) && !LIBGEN_FILES_TAB.test(html)) {
        throw host.fail('unreachable', `${hostOf(mirror)} answered without results${refusalOf(html)}`);
      }
      host.logger.log(`[annas-archive.libgen] [end] indexerId=${config.id} host=${hostOf(mirror)} bytes=${html.length} - page read`);
      return html;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      failures.push(message.startsWith(hostOf(mirror)) ? message : `${hostOf(mirror)}: ${message}`);
    }
  }
  throw host.fail('unreachable', failures.join('; ') || 'no Library Genesis mirror is configured');
}

function libgenReleases(html, formats) {
  const table = findTable(html, LIBGEN_RESULTS_TABLE_ID);
  if (!table) return [];
  return rowsOf(table)
    .map((row) => libgenRelease(row, formats))
    .filter(Boolean);
}

function libgenRelease(row, formats) {
  const cells = cellsOf(row);
  if (cells.length < LIBGEN_MIN_CELLS) return null;
  const md5 = LIBGEN_MD5_IN_HREF.exec(row)?.[1]?.toLowerCase();
  if (!md5) return null;

  const heading = firstAnchorText(cells[LG.title], 'edition.php');
  const format = cellText(cells[LG.format]).toLowerCase();
  if (!heading || !format || !formats.includes(format)) return null;

  const author = cleanAuthor(cellText(cells[LG.author]));
  const language = languageCode(cellText(cells[LG.language]));
  const isbn = rowIsbns(cells[LG.title]);

  return {
    guid: md5,
    ...readTitle(heading.replace(/\s*;\s*/g, ': ')),
    sizeBytes: parseSize(cellText(cells[LG.size])),
    seeders: null,
    leechers: null,
    format,
    ...(language ? { language } : {}),
    ...(author ? { author } : {}),
    ...(isbn ? { isbn } : {}),
    primaryFileCount: 1,
    fileCount: 1,
  };
}

/**
 * Author cells come from imported records: "A. de Saint-Exupéry,(Author);" is ordinary. Roles in
 * parentheses and the separators they leave behind are dropped, and each name is kept once.
 */
function cleanAuthor(value) {
  return value
    .replace(/\s*\((?:author|editor|translator|illustrator|ed\.?|trans\.?)\)/gi, '')
    .split(';')
    .map((name) => name.replace(/^[\s,]+|[\s,]+$/g, ''))
    .filter((name, index, all) => name && all.indexOf(name) === index)
    .join('; ');
}

function rowIsbns(cell) {
  const raw = LIBGEN_ROW_ISBNS.exec(cell ?? '')?.[1];
  if (!raw) return '';
  return raw
    .split(/[;,]/)
    .map((value) => value.replace(/[^0-9Xx]/g, '').toUpperCase())
    .filter((value, index, all) => (value.length === 10 || value.length === 13) && all.indexOf(value) === index)
    .join('; ');
}

/* ----------------------------------------------------------------------------------------------
 * Configuration
 * ------------------------------------------------------------------------------------------- */

function configuredFormats(config) {
  const raw = config.settings?.ebookFormats;
  const formats = splitList(typeof raw === 'string' && raw.trim() ? raw : DEFAULT_EBOOK_FORMATS)
    .map((format) => format.toLowerCase().replace(/^\./, ''))
    .filter((format, index, all) => ALLOWED_FORMATS.includes(format) && all.indexOf(format) === index);
  return formats.length ? formats : splitList(DEFAULT_EBOOK_FORMATS);
}

/** The main address first, then the fallbacks, each once. */
function mirrorsOf(config) {
  const extra = config.settings?.extraMirrors;
  return uniqueOrigins([config.baseUrl, ...splitList(typeof extra === 'string' ? extra : DEFAULT_MIRRORS)]);
}

function libgenMirrorsOf(config) {
  const raw = config.settings?.libgenMirrors;
  return uniqueOrigins(splitList(typeof raw === 'string' && raw.trim() ? raw : DEFAULT_LIBGEN_MIRRORS));
}

function libgenEnabled(config) {
  return config.settings?.libgenFallback !== false;
}

function solverUrl(config) {
  const raw = config.settings?.flareSolverrUrl;
  if (typeof raw !== 'string' || !raw.trim()) return null;
  return uniqueOrigins([raw])[0] ?? null;
}

function uniqueOrigins(values) {
  const origins = [];
  for (const value of values) {
    if (!value) continue;
    try {
      const text = String(value).trim();
      const origin = new URL(/^https?:\/\//i.test(text) ? text : `https://${text}`).origin;
      if (!origins.includes(origin)) origins.push(origin);
    } catch {
      // A malformed entry in a list is skipped rather than failing every search.
    }
  }
  return origins;
}

function splitList(value) {
  return String(value)
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

/* ----------------------------------------------------------------------------------------------
 * Releases and files
 * ------------------------------------------------------------------------------------------- */

function toFile(url, release, host) {
  const format = (release.format ?? '').toLowerCase();
  if (!format) throw host.fail('error', `"${release.title}" states no format, so there is no way to name the file it would be saved as`);
  return { url, fileName: `${sanitizeName(release.title)}.${format}`, sizeBytes: release.sizeBytes ?? null, format };
}

/** Shown with its subtitle, scored against the bare title, which is what a request states. */
function readTitle(heading) {
  const bare = stripParentheticals(heading.split(':')[0]);
  return { title: heading, ...(bare && bare !== heading ? { bookTitle: bare } : {}) };
}

function stripParentheticals(value) {
  return value.replace(/\s*[([][^)\]]*[)\]]/g, '').replace(/\s+/g, ' ').trim() || value.trim();
}

function md5Of(release) {
  const guid = typeof release.guid === 'string' ? release.guid.trim().toLowerCase() : '';
  return /^[a-f0-9]{32}$/.test(guid) ? guid : null;
}

function sanitizeName(title) {
  return (
    title
      .replace(/[^\p{L}\p{N}\s.-]/gu, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 120) || 'book'
  );
}

function logSearch(host, config, query, via, found, started) {
  host.logger.log(
    `[annas-archive.search] [end] indexerId=${config.id} via=${via} language=${query.language ?? 'any'} ` +
      `found=${found} durationMs=${Date.now() - started} - search finished`,
  );
}

/* ----------------------------------------------------------------------------------------------
 * Languages
 * ------------------------------------------------------------------------------------------- */

const LANGUAGE_BY_NAME = {
  arabic: 'ar', bulgarian: 'bg', catalan: 'ca', chinese: 'zh', croatian: 'hr', czech: 'cs', danish: 'da',
  dutch: 'nl', english: 'en', estonian: 'et', finnish: 'fi', french: 'fr', german: 'de', greek: 'el',
  hebrew: 'he', hindi: 'hi', hungarian: 'hu', indonesian: 'id', italian: 'it', japanese: 'ja', korean: 'ko',
  latin: 'la', norwegian: 'no', persian: 'fa', polish: 'pl', portuguese: 'pt', romanian: 'ro', russian: 'ru',
  serbian: 'sr', slovak: 'sk', slovenian: 'sl', spanish: 'es', swedish: 'sv', thai: 'th', turkish: 'tr',
  ukrainian: 'uk', vietnamese: 'vi',
};

/** Copied from the host's `release-scoring.ts` by way of the libgen plugin, so the two agree. */
const ISO_639_2_TO_1 = {
  alb: 'sq', sqi: 'sq', ara: 'ar', arm: 'hy', hye: 'hy', baq: 'eu', eus: 'eu', ben: 'bn', bul: 'bg',
  bur: 'my', mya: 'my', cat: 'ca', chi: 'zh', zho: 'zh', cze: 'cs', ces: 'cs', dan: 'da', dut: 'nl',
  nld: 'nl', est: 'et', fin: 'fi', geo: 'ka', kat: 'ka', ger: 'de', deu: 'de', gre: 'el', ell: 'el',
  heb: 'he', hin: 'hi', hrv: 'hr', hun: 'hu', ice: 'is', isl: 'is', ind: 'id', ita: 'it', jpn: 'ja',
  kor: 'ko', lav: 'lv', lit: 'lt', mac: 'mk', mkd: 'mk', mao: 'mi', mri: 'mi', may: 'ms', msa: 'ms',
  nor: 'no', per: 'fa', fas: 'fa', pol: 'pl', por: 'pt', rum: 'ro', ron: 'ro', rus: 'ru', slo: 'sk',
  slk: 'sk', slv: 'sl', spa: 'es', srp: 'sr', swe: 'sv', tha: 'th', tib: 'bo', bod: 'bo', tur: 'tr',
  ukr: 'uk', wel: 'cy', cym: 'cy', fre: 'fr', fra: 'fr', eng: 'en',
};

/**
 * A language cell as an ISO 639-1 code, or nothing. Anna's Archive writes "English [en]",
 * Library Genesis writes "English". Nothing rather than a guess, because a stated language is a
 * hard filter and a wrong one drops the release.
 */
function languageCode(value) {
  if (!value) return null;
  const bracketed = /\[([a-z]{2,3})(?:-[a-z0-9]+)?\]/i.exec(value)?.[1];
  if (bracketed) return normalizeLanguage(bracketed);
  const trimmed = value.trim().toLowerCase();
  const named = LANGUAGE_BY_NAME[trimmed.split(/[,;(/[]/)[0].trim()];
  if (named) return named;
  return /^[a-z]{2,3}$/.test(trimmed) ? normalizeLanguage(trimmed) : null;
}

/** The configured languages as ISO 639-1 codes; empty means every language. */
function acceptedLanguages(config) {
  const raw = config.settings?.languages;
  if (typeof raw !== 'string' || !raw.trim()) return [];
  return splitList(raw)
    .map((value) => normalizeLanguage(value))
    .filter((code, index, all) => /^[a-z]{2}$/.test(code) && all.indexOf(code) === index);
}

/** Unstated is kept: much of both catalogues carries no language, and the scorer keeps it too. */
function languageAccepted(accepted, released) {
  return accepted.length === 0 || !released || accepted.includes(normalizeLanguage(released));
}

/** A row that states no language is accepted, exactly as BookOrbit's scorer accepts it. */
function languagesAgree(requested, released) {
  if (!requested || !released) return true;
  return normalizeLanguage(requested) === normalizeLanguage(released);
}

function normalizeLanguage(value) {
  const subtag = value.toLowerCase().split(/[-_]/)[0];
  return ISO_639_2_TO_1[subtag] ?? subtag.slice(0, 2);
}

/* ----------------------------------------------------------------------------------------------
 * HTTP and markup helpers (tag handling from the libgen plugin, MIT)
 * ------------------------------------------------------------------------------------------- */

async function readBoundedText(response, limit) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (size < limit) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      size += value.byteLength;
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  const merged = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

async function discard(response) {
  await response.body?.cancel().catch(() => undefined);
}

function refusalOf(html) {
  const flattened = stripTags(String(html).slice(0, MAX_REFUSAL_BYTES));
  return flattened ? `: ${flattened.slice(0, MAX_REFUSAL_CHARS)}` : '';
}

function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/** The end of the tag at `start`, skipping any `>` inside a quoted attribute. */
function tagEnd(html, start) {
  let quote = '';
  for (let index = start; index < html.length; index += 1) {
    const character = html[index];
    if (quote) {
      if (character === quote) quote = '';
    } else if (character === '"' || character === "'") {
      quote = character;
    } else if (character === '>') {
      return index;
    }
  }
  return -1;
}

function findTable(html, id) {
  const marker = new RegExp(`<table[^>]*id=["']${id}["']`, 'i').exec(html);
  return marker ? tableFrom(html, marker.index) : null;
}

function findFirstTable(html) {
  const marker = /<table\b/i.exec(html);
  return marker ? tableFrom(html, marker.index) : null;
}

function tableFrom(html, start) {
  const open = tagEnd(html, start);
  if (open === -1) return null;
  const close = html.toLowerCase().indexOf('</table>', open);
  return close === -1 ? html.slice(open + 1) : html.slice(open + 1, close);
}

function rowsOf(table) {
  return [...table.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)].map((match) => match[1]).filter((row) => /<td\b/i.test(row));
}

function cellsOf(row) {
  const cells = [];
  const opens = /<td\b/gi;
  let match;
  while ((match = opens.exec(row)) !== null) {
    const open = tagEnd(row, match.index);
    if (open === -1) break;
    const close = row.toLowerCase().indexOf('</td>', open);
    if (close === -1) {
      cells.push(row.slice(open + 1));
      break;
    }
    cells.push(row.slice(open + 1, close));
    opens.lastIndex = close;
  }
  return cells;
}

/** The text of a cell's first span, or of the whole cell when it has none. */
function firstSpanText(cell) {
  if (cell === undefined) return '';
  const span = /<span\b/i.exec(cell);
  if (!span) return cellText(cell);
  const open = tagEnd(cell, span.index);
  if (open === -1) return '';
  const close = cell.toLowerCase().indexOf('</span>', open);
  return stripTags(close === -1 ? cell.slice(open + 1) : cell.slice(open + 1, close));
}

/**
 * The first span's own text, ignoring spans nested inside it. Anna's Archive nests related
 * editions inside the title span, and reading the whole of it folds them into the title.
 */
function firstSpanOwnText(cell) {
  if (cell === undefined) return '';
  const span = /<span\b/i.exec(cell);
  if (!span) return cellText(cell);
  const open = tagEnd(cell, span.index);
  if (open === -1) return '';
  const rest = cell.slice(open + 1);
  const stop = rest.search(/<\/?span\b/i);
  const own = stripTags(stop === -1 ? rest : rest.slice(0, stop));
  return own || firstSpanText(cell);
}

function firstAnchorText(cell, needle) {
  if (cell === undefined) return '';
  const opens = /<a\b/gi;
  let match;
  while ((match = opens.exec(cell)) !== null) {
    const open = tagEnd(cell, match.index);
    if (open === -1) return '';
    const tag = cell.slice(match.index, open + 1);
    const close = cell.toLowerCase().indexOf('</a>', open);
    if (close === -1) return '';
    if (tag.includes(needle)) return stripTags(cell.slice(open + 1, close));
    opens.lastIndex = close;
  }
  return '';
}

function cellText(cell) {
  return cell === undefined ? '' : stripTags(cell);
}

function stripTags(html) {
  let out = '';
  let cursor = 0;
  while (cursor < html.length) {
    const open = html.indexOf('<', cursor);
    if (open === -1) {
      out += html.slice(cursor);
      break;
    }
    out += html.slice(cursor, open);
    const close = tagEnd(html, open);
    if (close === -1) break;
    cursor = close + 1;
  }
  return decodeEntities(out).replace(/\s+/g, ' ').trim();
}

const NAMED_ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

function decodeEntities(value) {
  return value.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (whole, body) => {
    if (body[0] !== '#') return NAMED_ENTITIES[body.toLowerCase()] ?? whole;
    const code = body[1] === 'x' || body[1] === 'X' ? Number.parseInt(body.slice(2), 16) : Number.parseInt(body.slice(1), 10);
    return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
  });
}

/**
 * "702 kB", "1.2 MB", "1,012.3 kB". The thousands separator is stripped first: an unanchored
 * number match stops at the comma and reads that last one as 12.3 kB.
 */
function parseSize(value) {
  const match = /^\s*([\d.]+)\s*([KMGT]?i?B)/i.exec(String(value).replace(/,/g, ''));
  if (!match) return null;
  const units = { b: 1, kb: 1000, kib: 1024, mb: 1000 ** 2, mib: 1024 ** 2, gb: 1000 ** 3, gib: 1024 ** 3, tb: 1000 ** 4, tib: 1024 ** 4 };
  const bytes = Number(match[1]) * (units[match[2].toLowerCase()] ?? 1);
  return Number.isFinite(bytes) ? Math.round(bytes) : null;
}

