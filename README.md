# Anna's Archive for BookOrbit

An indexer plugin that lets [BookOrbit](https://github.com/bookorbit/bookorbit) search
[Anna's Archive](https://annas-archive.gl) for ebooks and comics, with Library Genesis as a
fallback catalogue. It is one dependency-free file with signed updates.

| Media | Credential | Grabs |
| --- | --- | --- |
| ebook | optional Anna's Archive account key | direct file |
| comic | optional Anna's Archive account key | direct file |

Which sources you point BookOrbit at, and whether you are entitled to what they hold, is your
decision and your responsibility.

## Why a fallback

Anna's Archive serves its search pages behind DDoS-Guard on every mirror. A plain request gets a
JavaScript check, and some networks get a manual CAPTCHA that no automated client can answer.
Its JSON API under `/dyn/` is not gated.

So each search goes through these steps:

1. **Anna's Archive** is searched first, through the table view. The main mirror is tried, then
   the fallback mirrors. A parked or seized domain is recognised and skipped.
2. If DDoS-Guard answers and you have set a **FlareSolverr** URL, FlareSolverr is asked to pass
   the check. When it says "solved" but returns the CAPTCHA page anyway, the plugin does not
   count that as a pass.
3. If the protection holds, **Library Genesis** is searched instead. Anna's Archive is then
   skipped for 15 minutes rather than asked again on every search.

Both catalogues name a file by its md5, so the download path is the same whichever one found it:

- with a **member's account key**: Anna's Archive's fast download API, which DDoS-Guard does not
  gate;
- otherwise, or when the fast downloads for the day are used up: the Library Genesis download
  service.

Library Genesis keeps listing files its file server no longer has: the download link then ends in
"File not found. The repositories may not be synchronized". So a Library Genesis link is checked
before it is handed over, by asking for its first bytes only, and each mirror is tried in turn.
When none has the file, the grab fails at once with "Library Genesis lists this file but its file
server does not have it. Try another release." instead of a bare "That URL answered 500" later.

Most of that is caught earlier, at search time: without an account key, up to 12 results are
checked the same way, three at a time, and those whose file is missing are not offered at all.
That matters for automatic fulfilment: a grab the plugin refuses makes BookOrbit skip every other
release from this indexer for the rest of the attempt, while a release that is never offered costs
nothing. Only a definite "not found" removes a result; a check that times out or hits an outage
keeps it. Searches wait at most 9 seconds for the checks, and the answers are remembered (missing
for 6 hours, present for 1 hour), so a second search is quicker and sees more of them.

An empty result from Anna's Archive ("No files found") counts as a real answer and returns
nothing. A page whose layout the plugin cannot read does not: it falls back to Library Genesis,
so a markup change never looks like "this book does not exist".

## Comics

A comic request is searched like an ebook request, with three differences:

- **Anna's Archive** is asked for its *Comic book* content type (`content=book_comic`).
- **Library Genesis** is asked for its Comics collection instead of the fiction and non-fiction
  ones. A comic's title there is the series, the issue number and the album title; the release is
  shown as `Asterix #15 - La Zizanie` and scored on the album title, which is what a request names.
- Both catalogues list many comics under the plain archive extension. A `.rar` is offered as
  `cbr`, a `.zip` as `cbz` and a `.7z` as `cb7`, which is what they are: BookOrbit counts only the
  comic names as comic formats, and the saved file is named after the format.

Audiobooks are still refused, as `unsupportedMedium`.

## Installing

In BookOrbit, open **Settings > System > Requests**, choose to install a plugin, and give it
[`indexers/annas-archive/index.mjs`](indexers/annas-archive/index.mjs). You can also copy the file
to the app data path and restart:

```
<APP_DATA_PATH>/plugins/indexers/annas-archive/index.mjs
```

`APP_DATA_PATH` is `/data` in the container. Then add an indexer of type **Anna's Archive** and
click **Test**. The test reports which catalogue answered and whether your key works.

## Settings

| Setting | Default | What it does |
| --- | --- | --- |
| Base URL | `https://annas-archive.gl` | The mirror tried first. |
| Account key | empty | Optional. A member's secret key (from your account page) enables fast downloads. |
| Fallback mirrors | `.gl`, `.pk`, `.gd` | Tried in order when the main mirror is down or parked. |
| FlareSolverr URL | empty | e.g. `http://192.168.0.10:8191`. A LAN address also needs **allow private addresses** on the indexer. |
| Search Library Genesis when blocked | on | Turn off to see the protection error instead. |
| Library Genesis mirrors | `libgen.li`, `libgen.bz` | Tried in order. |
| Ebook formats | epub, mobi, azw3, fb2 | `azw`, `djvu` and `pdf` can be added. |
| Comic formats | cbz, cbr, cb7 | `pdf` can be added. `.rar`, `.zip` and `.7z` files are offered under their comic name. |
| Accepted languages | empty (all) | ISO codes such as `en, fr`. Results stated in another language are dropped; results with no stated language are kept, as BookOrbit's own scoring keeps them. Also sent to Anna's Archive as its language filter. |

BookOrbit gives each indexer 20 seconds. A FlareSolverr solve takes 5 to 30 seconds, so the
plugin only starts one when it can still leave about 7 seconds for the Library Genesis fallback.

## Verifying

```bash
cd indexers/annas-archive && node verify.mjs
```

No network, no BookOrbit, and the run exits non-zero on failure. The Library Genesis pages, both
DDoS-Guard pages, the parked mirror and the API answer are live responses saved byte for byte. A
third-party contact address in the Library Genesis footer has been replaced. The Anna's Archive
search pages are written by hand, because the network the fixtures were made on only ever got the
CAPTCHA. Their headers say so.

## Releasing

Raise `version` in `indexers/annas-archive/index.mjs` and push to `main`. The
[workflow](.github/workflows/release.yml) runs `verify.mjs` and then waits for approval in the
`plugin-signing` environment. Once approved, it signs the committed file with the Ed25519 key that
environment holds, commits `updates/annas-archive.json`, and tags `annas-archive-v<version>`.
BookOrbit checks the SHA-256 and the signature against the public key pinned in the installed
copy before it updates.

`node scripts/release.mjs check` runs the same checks locally.

## Credits

The Library Genesis parsing and the release tooling come from
[orbit-plugins/bookorbit-plugins-extra](https://github.com/orbit-plugins/bookorbit-plugins-extra).
The Anna's Archive search and the protection detection follow
[calibrain/shelfmark](https://github.com/calibrain/shelfmark). Both are MIT; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
