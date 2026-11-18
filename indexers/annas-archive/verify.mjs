/**
 * Offline checks for the Anna's Archive plugin. No network, no BookOrbit: every request the plugin
 * makes is answered from `fixtures/` by a fake host, and the run exits non-zero on any failure.
 *
 *   node verify.mjs
 *
 * The Library Genesis pages, the DDoS-Guard pages, the parked mirror and the API answer are live
 * responses saved byte for byte (a third-party contact address in the Library Genesis footer is
 * replaced). The Anna's Archive search pages are written by hand, because the network they were
 * made on only ever got the CAPTCHA; their headers say so.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => readFileSync(join(here, 'fixtures', name), 'utf8');

let failures = 0;
let passed = 0;

function check(name, condition, detail = '') {
  if (condition) {
    passed += 1;
  } else {
    failures += 1;
    console.error(`FAIL ${name}${detail ? `: ${detail}` : ''}`);
  }
}

/** A fresh copy of the module per scenario, so the blocked-mirror memory never leaks between them. */
let generation = 0;
async function loadPlugin() {
  generation += 1;
  return (await import(`./index.mjs?scenario=${generation}`)).default;
}

const html = (body, status = 200, headers = {}) =>
  new Response(body, { status, headers: { 'content-type': 'text/html; charset=utf-8', ...headers } });
const json = (body, status = 200) => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const redirect = (location, server = 'ddos-guard') => new Response(null, { status: 302, headers: { location, server } });

/**
 * A host whose fetch is answered by the first route whose test matches the URL. Every request is
 * recorded, so a scenario can also assert what was NOT asked.
 */
function makeHost(routes) {
  const requests = [];
  const logs = [];
  return {
    requests,
    logs,
    async fetch(url, init = {}) {
      requests.push({ url, init });
      for (const [test, answer] of routes) {
        if (typeof test === 'string' ? url.includes(test) : test.test(url)) return typeof answer === 'function' ? answer(url, init) : answer();
      }
      throw this.fail('unreachable', `no route for ${url}`);
    },
    logger: { log: (message) => logs.push(message), warn: (message) => logs.push(message) },
    buildSearchText: (query) => [query.title, query.author].filter(Boolean).join(' '),
    async saveCredential() {},
    fail(failure, message) {
      const error = new Error(message);
      error.failure = failure;
      return error;
    },
  };
}

function config(overrides = {}) {
  return {
    id: 7,
    name: "Anna's Archive",
    baseUrl: 'https://annas-archive.gl',
    credential: null,
    allowPrivateAddress: false,
    categories: { ebook: [], audiobook: [] },
    settings: null,
    ...overrides,
  };
}

function query(overrides = {}) {
  return { title: 'Dune', author: 'Frank Herbert', isbn13: null, isbn13s: [], mediaKind: 'ebook', language: null, limit: 20, ...overrides };
}

const ANNAS = /annas-archive\.(gl|pk|gd)\/search/;
const LIBGEN = /libgen\.(li|bz)\/index\.php/;

async function rejects(promise) {
  try {
    await promise;
    return null;
  } catch (error) {
    return error;
  }
}

/* --- shape: the checks BookOrbit's loader applies before it ever calls the plugin -------------- */
{
  const plugin = await loadPlugin();
  check('apiVersion is 1', plugin.apiVersion === 1);
  check('type is a valid slug', /^[a-z0-9][a-z0-9-]{0,29}$/.test(plugin.type));
  check('version is semver', /^\d+\.\d+\.\d+$/.test(plugin.version));
  check('update key is 43 base64url chars', /^[A-Za-z0-9_-]{43}$/.test(plugin.update.ed25519PublicKey));
  check('manifest URL is https', plugin.update.manifestUrl.startsWith('https://'));
  check('exactly one grab method', typeof plugin.resolveFile === 'function' && plugin.fetchTorrentFile === undefined);
  check('declares ebook', plugin.mediaKinds.includes('ebook'));
  for (const field of plugin.settingsFields) {
    check(`field ${field.key} key`, /^[a-zA-Z][a-zA-Z0-9]{0,39}$/.test(field.key));
    if (field.format === 'list' && field.options) {
      const defaults = field.default.split(',').map((value) => value.trim());
      check(`field ${field.key} default within options`, defaults.every((value) => field.options.includes(value)));
      check(`field ${field.key} meets minItems`, defaults.length >= (field.minItems ?? 0));
    }
  }
}

/* --- Anna's Archive answers: its rows win, Library Genesis is never asked ----------------------- */
{
  const plugin = await loadPlugin();
  const host = makeHost([[ANNAS, () => html(fixture('annas-search-table.html'))]]);
  const releases = await plugin.search(query(), config(), host, new AbortController().signal);
  const dune = releases.find((release) => release.guid === '1111111111111111111111111111111a');

  check('annas: parses rows', releases.length === 3, `got ${releases.map((r) => r.guid).join(',')}`);
  check('annas: title ignores nested edition span', dune?.title === 'Dune', `got ${dune?.title}`);
  check('annas: author', dune?.author === 'Frank Herbert');
  check('annas: language from brackets', dune?.language === 'en');
  check('annas: size', dune?.sizeBytes === 1_200_000, `got ${dune?.sizeBytes}`);
  check('annas: no swarm counts, not zero', dune?.seeders === null && dune?.leechers === null);
  check('annas: thousands separator', releases.find((r) => r.language === 'fr')?.sizeBytes === 1_012_300);
  check('annas: pdf dropped by default formats', !releases.some((r) => r.format === 'pdf'));
  check('annas: duplicate md5 kept once', releases.filter((r) => r.guid === dune?.guid).length === 1);
  check('annas: catalogue descriptor skipped', !releases.some((r) => r.title === 'Book/Online Audio'));
  check('annas: row without language accepted', releases.some((r) => r.guid === '5555555555555555555555555555555e'));
  check('annas: small real page is not a challenge', !host.requests.some((r) => LIBGEN.test(r.url)));
  check('annas: bookTitle drops parenthetical', releases.find((r) => r.language === 'fr')?.bookTitle === 'Dune');

  const url = new URL(host.requests[0].url);
  check('annas: table view', url.searchParams.get('display') === 'table');
  check('annas: title and author terms', url.searchParams.get('termval_1') === 'Dune' && url.searchParams.get('termval_2') === 'Frank Herbert');
  check('annas: no redirect following', host.requests[0].init.redirect === 'manual');
}

/* --- language and formats -------------------------------------------------------------------- */
{
  const plugin = await loadPlugin();
  const host = makeHost([[ANNAS, () => html(fixture('annas-search-table.html'))]]);
  const releases = await plugin.search(query({ language: 'fre' }), config({ settings: { ebookFormats: 'epub,pdf' } }), host, undefined);
  check('language: fre keeps French and unstated only', releases.every((r) => !r.language || r.language === 'fr'), JSON.stringify(releases.map((r) => r.language)));
  check('language: sent to the site as fr', new URL(host.requests[0].url).searchParams.get('lang') === 'fr');
  check('formats: configured formats sent', new URL(host.requests[0].url).searchParams.getAll('ext').join() === 'epub,pdf');
}

/* --- accepted languages ------------------------------------------------------------------------ */
{
  const plugin = await loadPlugin();
  const host = makeHost([
    [ANNAS, (url) => redirect(`${new URL(url).pathname}?check=1`)],
    [LIBGEN, () => html(fixture('libgen-dune.html'))],
  ]);
  const settings = { languages: 'en, fr', ebookFormats: 'epub,mobi,azw3,fb2,pdf,djvu' };
  const all = await plugin.search(query({ limit: 50 }), config({ settings: { ebookFormats: settings.ebookFormats } }), makeHost([
    [ANNAS, (url) => redirect(`${new URL(url).pathname}?check=1`)],
    [LIBGEN, () => html(fixture('libgen-dune.html'))],
  ]), undefined);
  const kept = await plugin.search(query({ limit: 50 }), config({ settings }), host, undefined);
  check('languages: fixture holds others to drop', all.some((r) => r.language && !['en', 'fr'].includes(r.language)), JSON.stringify(all.map((r) => r.language)));
  check('languages: only en, fr or unstated kept', kept.length > 0 && kept.every((r) => !r.language || ['en', 'fr'].includes(r.language)), JSON.stringify(kept.map((r) => r.language)));
  check('languages: nothing in en/fr lost', kept.length === all.filter((r) => !r.language || ['en', 'fr'].includes(r.language)).length);

  const annas = await loadPlugin();
  const annasHost = makeHost([[ANNAS, () => html(fixture('annas-search-table.html'))]]);
  const rows = await annas.search(query(), config({ settings: { languages: 'fre' } }), annasHost, undefined);
  check('languages: 639-2 code accepted', rows.every((r) => !r.language || r.language === 'fr') && rows.some((r) => r.language === 'fr'));
  check('languages: unstated row kept', rows.some((r) => r.guid === '5555555555555555555555555555555e'));
  const sent = new URL(annasHost.requests[0].url).searchParams.getAll('lang');
  check('languages: sent to Anna\'s Archive', sent.join() === 'fr', sent.join());

  const both = makeHost([[ANNAS, () => html(fixture('annas-search-table.html'))]]);
  await (await loadPlugin()).search(query(), config({ settings: { languages: 'en,fr' } }), both, undefined);
  check('languages: several sent as repeated lang', new URL(both.requests[0].url).searchParams.getAll('lang').join() === 'en,fr');

  const requested = makeHost([[ANNAS, () => html(fixture('annas-search-table.html'))]]);
  await (await loadPlugin()).search(query({ language: 'en' }), config({ settings: { languages: 'en,fr' } }), requested, undefined);
  check('languages: a request\'s own language wins in the URL', new URL(requested.requests[0].url).searchParams.getAll('lang').join() === 'en');
}

/* --- the empty answer is an answer ----------------------------------------------------------- */
{
  const plugin = await loadPlugin();
  const host = makeHost([[ANNAS, () => html(fixture('annas-no-files.html'))]]);
  const releases = await plugin.search(query(), config(), host, undefined);
  check('no files: empty list', Array.isArray(releases) && releases.length === 0);
  check('no files: Library Genesis not asked', !host.requests.some((r) => LIBGEN.test(r.url)));
}

/* --- DDoS-Guard's 302 to check=1: fall back to Library Genesis, then stop asking ------------------ */
{
  const plugin = await loadPlugin();
  const host = makeHost([
    [ANNAS, (url) => redirect(`${new URL(url).pathname}?q=dune&check=1`)],
    [LIBGEN, () => html(fixture('libgen-dune.html'))],
  ]);
  const releases = await plugin.search(query(), config(), host, undefined);
  check('challenge: fell back to libgen', releases.length > 0, `got ${releases.length}`);
  check('challenge: only epub-family formats', releases.every((r) => ['epub', 'mobi', 'azw3', 'fb2'].includes(r.format)));
  check('challenge: md5 guids', releases.every((r) => /^[a-f0-9]{32}$/.test(r.guid)));
  check('challenge: one Anna\'s Archive request, not one per mirror', host.requests.filter((r) => ANNAS.test(r.url)).length === 1);
  const first = releases.find((r) => r.guid === '805290ae7791f6fa5fabf9128f12e632');
  check('libgen: isbn list read', first?.isbn?.includes('9780765322739'), first?.isbn);
  check('libgen: language name mapped', first?.language === 'en');
  check('libgen: size', first?.sizeBytes === 695_000, `got ${first?.sizeBytes}`);
  check('libgen: author roles and stray separators cleaned', releases.every((r) => !/\(Author\)|,\s*$|;\s*$/.test(r.author ?? '')), JSON.stringify(releases.map((r) => r.author)));

  const before = host.requests.length;
  await plugin.search(query(), config(), host, undefined);
  const again = host.requests.slice(before);
  check('cooldown: second search skips Anna\'s Archive', !again.some((r) => ANNAS.test(r.url)) && again.some((r) => LIBGEN.test(r.url)));
}

/* --- the manual CAPTCHA, with the fallback off, fails loudly and says why --------------------- */
{
  const plugin = await loadPlugin();
  const host = makeHost([[ANNAS, () => html(fixture('ddos-guard-captcha.html'), 403, { server: 'ddos-guard' })]]);
  const error = await rejects(plugin.search(query(), config({ settings: { libgenFallback: false } }), host, undefined));
  check('captcha: rejects', error !== null);
  check('captcha: unreachable, not an empty list', error?.failure === 'unreachable');
  check('captcha: names the CAPTCHA', /manual CAPTCHA/.test(error?.message ?? ''), error?.message);

  const again = await rejects(plugin.search(query(), config({ settings: { libgenFallback: false } }), host, undefined));
  check('captcha: cooldown keeps the real reason', /manual CAPTCHA/.test(again?.message ?? '') && /not asked again/.test(again?.message ?? ''), again?.message);
  check('captcha: cooldown asks nothing', host.requests.length === 1);
}

/* --- the JS challenge body (no redirect) is recognised too ------------------------------------- */
{
  const plugin = await loadPlugin();
  const host = makeHost([[ANNAS, () => html(fixture('ddos-guard-js-challenge.html'), 403, { server: 'ddos-guard' })]]);
  const error = await rejects(plugin.search(query(), config({ settings: { libgenFallback: false } }), host, undefined));
  check('js challenge: suggests FlareSolverr', /FlareSolverr/.test(error?.message ?? ''), error?.message);
}

/* --- FlareSolverr passes the check ------------------------------------------------------------ */
{
  const plugin = await loadPlugin();
  const host = makeHost([
    [ANNAS, (url) => redirect(`${new URL(url).pathname}?check=1`)],
    ['192.168.0.10:8191/v1', () => json({ status: 'ok', message: 'Challenge solved!', solution: { status: 200, response: fixture('annas-search-table.html') } })],
  ]);
  const releases = await plugin.search(query(), config({ settings: { flareSolverrUrl: 'http://192.168.0.10:8191' } }), host, undefined);
  check('flaresolverr: rows from Anna\'s Archive', releases.length === 3);
  const call = host.requests.find((r) => r.url.includes(':8191'));
  const body = JSON.parse(call?.init.body ?? '{}');
  check('flaresolverr: request.get of the search URL', body.cmd === 'request.get' && ANNAS.test(body.url));
  check('flaresolverr: timeout leaves room for the fallback', body.maxTimeout > 0 && body.maxTimeout <= 10_000, `got ${body.maxTimeout}`);
}

/* --- FlareSolverr says "solved" and brings back the CAPTCHA: not believed ---------------------- */
{
  const plugin = await loadPlugin();
  const host = makeHost([
    [ANNAS, (url) => redirect(`${new URL(url).pathname}?check=1`)],
    [':8191/v1', () => json({ status: 'ok', message: 'Challenge solved!', solution: { status: 200, response: fixture('ddos-guard-captcha.html') } })],
    [LIBGEN, () => html(fixture('libgen-dune.html'))],
  ]);
  const releases = await plugin.search(query(), config({ settings: { flareSolverrUrl: 'http://192.168.0.10:8191' } }), host, undefined);
  check('false solve: fell back to libgen', releases.length > 0 && host.requests.some((r) => LIBGEN.test(r.url)));
  check('false solve: logged as CAPTCHA', host.logs.some((line) => /manual CAPTCHA/.test(line)));
}

/* --- a parked mirror is skipped for the next one ----------------------------------------------- */
{
  const plugin = await loadPlugin();
  const host = makeHost([
    ['annas-archive.li/search', () => html(fixture('parked-mirror.html'))],
    [ANNAS, () => html(fixture('annas-search-table.html'))],
  ]);
  const releases = await plugin.search(query(), config({ baseUrl: 'https://annas-archive.li' }), host, undefined);
  check('parked: next mirror answered', releases.length === 3);
  check('parked: tried .li first', host.requests[0].url.includes('annas-archive.li'));
}

/* --- a layout Anna's Archive changed is not "nothing found" ------------------------------------- */
{
  const plugin = await loadPlugin();
  const host = makeHost([
    [ANNAS, () => html(fixture('annas-layout-drift.html').replace('<main>', '<main><a href="/datasets">x</a>'))],
    [LIBGEN, () => html(fixture('libgen-dune.html'))],
  ]);
  const releases = await plugin.search(query(), config(), host, undefined);
  check('drift: fell back to libgen instead of returning nothing', releases.length > 0);
  check('drift: logged', host.logs.some((line) => /layout may have changed/.test(line)));
}

/* --- Library Genesis: a mirror whose database refuses moves on to the next ----------------------- */
{
  const plugin = await loadPlugin();
  const host = makeHost([
    [ANNAS, (url) => redirect(`${new URL(url).pathname}?check=1`)],
    ['libgen.li/index.php', () => html(fixture('libgen-db-error.html'))],
    ['libgen.bz/index.php', () => html(fixture('libgen-dune.html'))],
  ]);
  const releases = await plugin.search(query(), config(), host, undefined);
  check('libgen mirrors: second mirror answered', releases.length > 0);
}

/* --- Library Genesis: genuinely nothing, and both catalogues down -------------------------------- */
{
  const plugin = await loadPlugin();
  const host = makeHost([
    [ANNAS, (url) => redirect(`${new URL(url).pathname}?check=1`)],
    [LIBGEN, () => html(fixture('libgen-no-hits.html'))],
  ]);
  const releases = await plugin.search(query({ title: 'zzqxqvbnonexistenttitle', author: null }), config(), host, undefined);
  check('libgen no hits: empty, not an error', releases.length === 0);

  const down = await loadPlugin();
  const downHost = makeHost([
    [ANNAS, (url) => redirect(`${new URL(url).pathname}?check=1`)],
    [LIBGEN, () => html(fixture('libgen-db-error.html'))],
  ]);
  const error = await rejects(down.search(query(), config(), downHost, undefined));
  check('both down: unreachable', error?.failure === 'unreachable', error?.message);
  check('both down: both reasons given', /DDoS-Guard/.test(error?.message ?? '') && /Library Genesis/.test(error?.message ?? ''), error?.message);
}

/* --- an ISBN goes first on Library Genesis ------------------------------------------------------ */
{
  const plugin = await loadPlugin();
  const host = makeHost([
    [ANNAS, (url) => redirect(`${new URL(url).pathname}?check=1`)],
    [/libgen\.li\/index\.php.*columns%5B%5D=i/, () => html(fixture('libgen-isbn.html'))],
    [LIBGEN, () => html(fixture('libgen-dune.html'))],
  ]);
  await plugin.search(query({ isbn13: '9780441013593' }), config(), host, undefined);
  const libgen = host.requests.filter((r) => LIBGEN.test(r.url)).map((r) => new URL(r.url));
  check('isbn: first libgen pass is the ISBN column', libgen[0]?.searchParams.get('req') === '9780441013593' && libgen[0]?.searchParams.getAll('columns[]').join() === 'i');
}

/* --- audiobooks are refused, not searched ------------------------------------------------------ */
{
  const plugin = await loadPlugin();
  const host = makeHost([]);
  const error = await rejects(plugin.search(query({ mediaKind: 'audiobook' }), config(), host, undefined));
  check('audiobook: unsupportedMedium', error?.failure === 'unsupportedMedium' && host.requests.length === 0);
}

/* --- comics: their own formats, their own collection, archives under their comic name ---------- */
{
  const plugin = await loadPlugin();
  check('declares comic', plugin.mediaKinds.includes('comic'));
  const field = plugin.settingsFields.find((f) => f.key === 'comicFormats');
  check('comic formats default to the three comic archives', field?.default === 'cbz,cbr,cb7', field?.default);
}
{
  const plugin = await loadPlugin();
  const host = makeHost([[ANNAS, () => html(fixture('annas-comics-table.html'))]]);
  const releases = await plugin.search(query({ title: 'La Zizanie', author: null, mediaKind: 'comic' }), config(), host, undefined);
  const url = new URL(host.requests[0].url);
  check('comic annas: content filter sent', url.searchParams.get('content') === 'book_comic', url.href);
  check('comic annas: archive extensions asked too', url.searchParams.getAll('ext').join() === 'cbz,cbr,cb7,rar,zip,7z', url.searchParams.getAll('ext').join());
  check('comic annas: four comic rows kept', releases.length === 4, releases.map((r) => `${r.guid.slice(0, 2)}:${r.format}`).join());
  check('comic annas: rar offered as cbr', releases.find((r) => r.guid.startsWith('c2'))?.format === 'cbr');
  check('comic annas: zip offered as cbz', releases.find((r) => r.guid.startsWith('c4'))?.format === 'cbz');
  check('comic annas: pdf left out by default', !releases.some((r) => r.format === 'pdf'));
  check('comic annas: an ebook row is not a comic', !releases.some((r) => r.guid.startsWith('c6')));
}
{
  const plugin = await loadPlugin();
  const host = makeHost([[ANNAS, () => html(fixture('annas-comics-table.html'))]]);
  const releases = await plugin.search(query({ mediaKind: 'comic' }), config({ settings: { comicFormats: 'cbz, pdf' } }), host, undefined);
  check('comic formats: configured list and its aliases sent', new URL(host.requests[0].url).searchParams.getAll('ext').join() === 'cbz,pdf,zip');
  check('comic formats: pdf kept when chosen, cbr dropped', releases.map((r) => r.format).sort().join() === 'cbz,cbz,pdf', releases.map((r) => r.format).join());
}
{
  const plugin = await loadPlugin();
  const host = makeHost([[ANNAS, () => html(fixture('annas-search-table.html'))]]);
  await plugin.search(query(), config(), host, undefined);
  check('ebook annas: no content filter', !new URL(host.requests[0].url).searchParams.has('content'));
}
{
  const plugin = await loadPlugin();
  const host = makeHost([
    [ANNAS, () => html(fixture('ddos-guard-captcha.html'), 403, { server: 'ddos-guard' })],
    [LIBGEN, () => html(fixture('libgen-comics.html'))],
  ]);
  const releases = await plugin.search(query({ title: 'Asterix', author: null, mediaKind: 'comic', limit: 50 }), config(), host, undefined);
  const libgen = new URL(host.requests.find((r) => LIBGEN.test(r.url)).url);
  const first = releases.find((r) => r.guid === releases[0]?.guid);
  check('comic libgen: comics collection only', libgen.searchParams.getAll('topics[]').join() === 'c', libgen.searchParams.getAll('topics[]').join());
  check('comic libgen: every row read', releases.length === 25, `got ${releases.length}`);
  check('comic libgen: only comic formats', releases.every((r) => ['cbz', 'cbr', 'cb7'].includes(r.format)), [...new Set(releases.map((r) => r.format))].join());
  check('comic libgen: rar rows offered as cbr', releases.filter((r) => r.format === 'cbr').length === 24);
  check('comic libgen: series, number and album title', first?.title === 'Asterix Y Obelix #15 - Asterix La Cizana', first?.title);
  check('comic libgen: album title is what gets scored', first?.bookTitle === 'Asterix La Cizana', first?.bookTitle);
  check('comic libgen: no title is just an issue number', !releases.some((r) => r.title.startsWith('#')));
}
{
  const plugin = await loadPlugin();
  const host = makeHost([
    [ANNAS, () => html(fixture('ddos-guard-captcha.html'), 403, { server: 'ddos-guard' })],
    [LIBGEN, () => html(fixture('libgen-dune.html'))],
  ]);
  await plugin.search(query(), config(), host, undefined);
  const libgen = new URL(host.requests.find((r) => LIBGEN.test(r.url)).url);
  check('ebook libgen: fiction and non-fiction collections', libgen.searchParams.getAll('topics[]').join() === 'l,f');
}
{
  const plugin = await loadPlugin();
  const host = makeHost([['libgen.download/api/download', () => new Response('Rar!', { status: 200 })]]);
  const comic = { guid: 'c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2', title: 'Astérix - La Zizanie', format: 'cbr', sizeBytes: 88_000_000, seeders: null, leechers: null };
  const file = await plugin.resolveFile(comic, config(), host, undefined);
  check('comic resolve: saved under the comic extension', file.fileName === 'Astérix - La Zizanie.cbr' && file.format === 'cbr', file.fileName);
}

/* --- resolveFile ------------------------------------------------------------------------------ */
const release = { guid: '805290ae7791f6fa5fabf9128f12e632', title: 'Sisterhood of Dune: Brian Herbert', format: 'epub', sizeBytes: 695_000, seeders: null, leechers: null };
const serviceServes = () => new Response('PK\u0003\u0004', { status: 200, headers: { 'content-type': 'application/epub+zip' } });
const serviceRedirects = () => new Response(null, { status: 302, headers: { location: 'https://libgen.vg/ads.php?md5=805290ae7791f6fa5fabf9128f12e632' } });
{
  const plugin = await loadPlugin();
  const host = makeHost([['libgen.download/api/download', serviceServes]]);
  const file = await plugin.resolveFile(release, config(), host, undefined);
  check('resolve: no key goes to libgen.download', file.url === 'https://libgen.download/api/download?id=805290ae7791f6fa5fabf9128f12e632', file.url);
  check('resolve: file name from title', file.fileName === 'Sisterhood of Dune Brian Herbert.epub', file.fileName);
  check('resolve: service asked without following redirects', host.requests[0]?.init.redirect === 'manual');
}
{
  const plugin = await loadPlugin();
  const host = makeHost([
    ['libgen.download/api/download', serviceRedirects],
    ['libgen.li/ads.php', () => html(fixture('libgen-ads-db-error.html'), 500)],
    ['libgen.bz/ads.php', () => html(fixture('libgen-ads.html'))],
  ]);
  const file = await plugin.resolveFile(release, config(), host, undefined);
  check('resolve: dead redirect falls back to a mirror get.php link', /^https:\/\/libgen\.bz\/get\.php\?md5=[a-f0-9]{32}&key=[A-Za-z0-9]+$/.test(file.url), file.url);
  check('resolve: never follows the service to libgen.vg', !host.requests.some((r) => r.url.includes('libgen.vg')));
  const ads = host.requests.find((r) => r.url.includes('libgen.bz/ads.php'));
  check('resolve: ad page asked with a same-origin Referer', ads?.init.headers?.Referer === 'https://libgen.bz/', JSON.stringify(ads?.init.headers));
}
{
  const plugin = await loadPlugin();
  const host = makeHost([
    ['libgen.download/api/download', serviceRedirects],
    [/libgen\.(li|bz)\/ads\.php/, () => html(fixture('libgen-ads-db-error.html'), 500)],
  ]);
  const error = await rejects(plugin.resolveFile(release, config(), host, undefined));
  check('resolve: no mirror offers it is unreachable, with reasons', error?.failure === 'unreachable' && /libgen\.bz/.test(error?.message ?? ''), error?.message);
}
/* --- the get.php link is checked before it is handed over -------------------------------------- */
const fileServes = () => new Response('PK\u0003\u0004', { status: 206, headers: { 'content-type': 'application/octet-stream' } });
const fileMissing = () => html(fixture('libgen-file-not-found.html'), 500);
const adsBoth = [
  ['libgen.download/api/download', serviceRedirects],
  [/libgen\.(li|bz)\/ads\.php/, () => html(fixture('libgen-ads.html'))],
];
{
  const plugin = await loadPlugin();
  const host = makeHost([...adsBoth.slice(0, 1), ['libgen.li/ads.php', () => html(fixture('libgen-ads.html'))], ['get.php', fileServes]]);
  const file = await plugin.resolveFile(release, config(), host, undefined);
  const probe = host.requests.find((r) => r.url.includes('get.php'));
  check('probe: a served link is handed over', /\/get\.php\?md5=/.test(file.url), file.url);
  check('probe: only the first bytes are asked for', probe?.init.headers?.Range === 'bytes=0-15', JSON.stringify(probe?.init.headers));
  check('probe: asked with a same-origin Referer', probe?.init.headers?.Referer === 'https://libgen.li/');
}
{
  const plugin = await loadPlugin();
  const host = makeHost([...adsBoth, ['get.php', fileMissing]]);
  const error = await rejects(plugin.resolveFile(release, config(), host, undefined));
  check('probe: a listed but missing file is unreachable', error?.failure === 'unreachable', error?.message);
  check('probe: says the file server does not have it', /lists this file but its file server does not have it/.test(error?.message ?? ''), error?.message);
  check('probe: suggests another release', /Try another release/.test(error?.message ?? ''), error?.message);
  check('probe: every mirror was tried', host.requests.filter((r) => r.url.includes('get.php')).length === 2);
}
{
  const plugin = await loadPlugin();
  const host = makeHost([...adsBoth, ['libgen.li/get.php', fileMissing], ['libgen.bz/get.php', fileServes]]);
  const file = await plugin.resolveFile(release, config(), host, undefined);
  check('probe: the next mirror serves it', file.url.startsWith('https://libgen.bz/get.php'), file.url);
}
{
  const plugin = await loadPlugin();
  const host = makeHost([...adsBoth, ['get.php', () => html('<html><body><h1>503 Service Temporarily Unavailable</h1></body></html>', 503)]]);
  const error = await rejects(plugin.resolveFile(release, config(), host, undefined));
  check('probe: an outage is not reported as a missing file', !/does not have it/.test(error?.message ?? '') && /answered 503/.test(error?.message ?? ''), error?.message);
}
{
  const plugin = await loadPlugin();
  const host = makeHost(adsBoth);
  const file = await plugin.resolveFile(release, config(), host, undefined);
  check('probe: no answer at all keeps the link', /\/get\.php\?md5=/.test(file.url), file.url);
}

{
  const plugin = await loadPlugin();
  const host = makeHost([['/dyn/api/fast_download.json', () => json({ download_url: 'https://fast.example/abc.epub', account_fast_download_info: {} })]]);
  const file = await plugin.resolveFile(release, config({ credential: 'member-key' }), host, undefined);
  check('resolve: member key uses the fast link', file.url === 'https://fast.example/abc.epub');
  check('resolve: key sent to the API', new URL(host.requests[0].url).searchParams.get('key') === 'member-key');
}
{
  const plugin = await loadPlugin();
  const host = makeHost([['/dyn/api/fast_download.json', () => json(fixture('fast-download-invalid-key.json'), 401)]]);
  const error = await rejects(plugin.resolveFile(release, config({ credential: 'nope' }), host, undefined));
  check('resolve: invalid key is unauthorized', error?.failure === 'unauthorized', error?.message);
}
{
  const plugin = await loadPlugin();
  const host = makeHost([
    ['/dyn/api/fast_download.json', () => json({ download_url: null, error: 'No downloads left' }, 429)],
    ['libgen.download/api/download', serviceServes],
  ]);
  const file = await plugin.resolveFile(release, config({ credential: 'tired-key' }), host, undefined);
  check('resolve: out of fast downloads falls back to libgen', file.url.startsWith('https://libgen.download/'));
}
{
  const plugin = await loadPlugin();
  const error = await rejects(plugin.resolveFile({ ...release, guid: 'not-an-md5' }, config(), makeHost([]), undefined));
  check('resolve: refuses a guid that is not an md5', error?.failure === 'error');
}

/* --- test() ----------------------------------------------------------------------------------- */
{
  const plugin = await loadPlugin();
  const host = makeHost([
    [ANNAS, (url) => redirect(`${new URL(url).pathname}?check=1`)],
    [LIBGEN, () => html(fixture('libgen-dune.html'))],
  ]);
  const result = await plugin.test(config(), host);
  check('test: succeeds through libgen', result.success === true && /Library Genesis/.test(result.indexerName ?? ''), JSON.stringify(result));
}
{
  const plugin = await loadPlugin();
  const host = makeHost([
    [ANNAS, () => html(fixture('annas-search-table.html'))],
    ['/dyn/api/fast_download.json', () => json(fixture('fast-download-invalid-key.json'), 401)],
  ]);
  const result = await plugin.test(config({ credential: 'nope' }), host);
  check('test: bad key fails the test', result.success === false && /rejected/.test(result.error ?? ''), JSON.stringify(result));
}

console.log(`${passed} passed, ${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
