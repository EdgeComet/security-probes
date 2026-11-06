# Security probes

`probes.md` lists the paths scanners request to find files that must never be public: `.env`, `.git`, backups, database dumps, debug logs, `phpinfo()` pages, cloud credentials, and endpoints that read files or run code.

Every path on the list should answer `404` or `403`. A `200` that returns the file is a leak.

- Raw list: https://edgecomet.com/public/probes.md
- Sources: probe requests seen across [EdgeComet](#edgecomet) sites, plus [SecLists](https://github.com/danielmiessler/SecLists), [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) and [SANS ISC / DShield](https://isc.sans.edu) reports.
- The first line of `probes.md` gives the date of the last update.

## Format

One section per category, in match order: Secrets & Keys, Source Control, Config & Backups, Debug & Server Info, File-Read Exploits, Code-Execution Exploits, Admin & Login, Other dotfiles. Each section is one `text` block.

| Line | Example | Meaning |
|---|---|---|
| Path | `/.env` | Request it as is. Paths seen on 3 or more EdgeComet sites come first, most widely seen first. |
| Pattern | `*/.env*` | `*` matches any characters, `/` included. |
| Alternatives | `/{www,backup}.{zip,tar.gz}` | One path per combination. `{host}` is the site's host, the host without `www.`, or its first label. `{year}` is 1900 to 2099. |
| Query payload | `?../` | The decoded query string contains `../`. Counts only when the path matches nothing. |

Matching rules:

1. Lowercase and percent-decode the path, without the query string: `/Admin%2F.ENV` is `/admin/.env`.
2. Ignore a trailing slash: `/phpinfo/` matches `/phpinfo`. Exception: `/credentials`.
3. The first matching section wins: `/@fs/root/.env` is Secrets & Keys, not File-Read Exploits.
4. Other dotfiles (`*/.*`) never covers `/.well-known/` or an empty-slug link like `/blog/category/.html`.

## Check your site

Run it only on sites you own or may test.

```sh
BASE=https://example.com
{
  printf '%s\n' /zz-missing-page-check /zz-missing-file-check.txt /zz-missing-dir-check/
  curl -fsS https://edgecomet.com/public/probes.md |
    awk '/^```text/ { inblock = 1; next }
         /^```/     { inblock = 0; next }
         inblock && NF && !/[*{]/ && !/^[?]/'
} | while IFS= read -r probe; do
  printf '%s\t%s\n' "$(curl -gs --path-as-is -o /dev/null --max-time 20 \
    -w '%{http_code}\t%{content_type}\t%{size_download}' "$BASE$probe")" "$probe"
done
```

Each output line is status, content type, size and path. The first three lines request made-up URLs: that is how your site answers a missing page. Keep `-g` and `--path-as-is`, or curl rejects paths with brackets and rewrites `../`.

| Answer | Verdict |
|---|---|
| `404`, `410` | Healthy. |
| Other 4xx, 3xx | Blocked or redirected. Fine. |
| 5xx, `000` | The server failed or did not answer. Look at it. |
| 2xx like the made-up URLs (same content type, title, about the same size) | Catch-all page, not a leak. Still a soft 404. |
| 2xx with `text/plain`, `application/octet-stream`, JSON, an archive or no content type | Leak. |
| 2xx with an image | Not a leak. |
| 2xx HTML unlike the made-up URLs | Open it: a `phpinfo()` or debug page, or a real page at that path. |

If a file leaked, remove it, rotate every password, key and token it held, and make the path answer `404`.

A CDN rule covers only traffic through the CDN. Repeat the check against the origin: add `--resolve example.com:443:<origin IP>` to the curl request.

### With Claude Code

```text
Check my site https://example.com for exposed sensitive files.
1. Download https://edgecomet.com/public/probes.md with curl, not a web fetch.
2. From the fenced code blocks, keep lines with no "*", no "{" and no leading "?".
3. Request /zz-missing-page-check, /zz-missing-file-check.txt and
   /zz-missing-dir-check/ as the baseline.
4. GET every kept path with curl -gs --path-as-is, without following redirects.
   Record status, content type, size and the HTML title.
5. List every 2xx that differs from the baseline, non-HTML answers first.
6. Never print file contents.
```

## Not on the list

These look like probes but are real pages on many sites: `/credentials/`, `/wp-json/wp/v2/users`, `/.well-known/*` (a `.php` file there is on the list), `/llms.txt`, `/graphql`, `/console`, `/sitemap.xml.gz`, archives below the root like `/downloads/data.zip`, empty-slug links like `/blog/category/.html`, Magento URLs ending in `~/`.

## EdgeComet

We built this list from the scanner traffic [EdgeComet](https://edgecomet.com) sees across its sites. EdgeComet checks it on every site it serves: the [Security report](https://edgecomet.com/docs/log-analyzer/bad-bots-security) shows each probe and how the site answered, and the [Sensitive file exposed](https://edgecomet.com/docs/alerts/templates#sensitive-file-exposed) alert emails you when a probed path returns a file.

Scanners are on the rise, and AI-built apps leave more of these files in the web root. If your tool sees how sites answer, add this check now: one flagged probe can stop a leak before someone else finds it.

## Contributing

Open a pull request that adds the path to its section and says where you saw it: your logs, a honeypot, a scanner template or an advisory. We test every change against EdgeComet traffic for false positives. `probes.md` is generated, so an accepted change goes into the generator and the file is regenerated.

## License

MIT, see [LICENSE](LICENSE). Part of the vocabulary comes from SecLists (MIT) and nuclei-templates (MIT).
