# SecWire, a Telegraph CVE lookup miner

SecWire answers the Telegraph **CVE_LOOKUP** intent. Give it a CVE id and it returns the
CVSS base score and severity, the affected vendor or product, the assigned CWE weaknesses,
the published date and whether a fix is noted, as one plain sentence followed by a full
Readings block. It is a Cloudflare Worker with no database and no API key.

## Data sources

Two public sources are fetched together at request time and merged. Neither needs a key.

- **CIRCL**, `https://cve.circl.lu/api/cve/<id>`, returns the raw CVE 5.1 record with the assigning
  authority's own description, the affected products and the references. The CVE Program data
  underneath is CC BY 4.0. The instance asks automated clients to send a User-Agent with a contact,
  which this worker does.
- **NVD 2.0**, `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>`, is the authoritative
  source for the CVSS base score and the CWE. NIST publications carry no copyright in the United
  States. Its terms ask that a specific line appear in any application that uses the API, and this
  miner publishes it: *This product uses the NVD API but is not endorsed or certified by the NVD.*
  Its keyless limit is 5 requests in a rolling 30 second window, which is why CIRCL leads and NVD is
  the corroborating read. That limit is recorded as an open item in
  [`DATA-SOURCES.md`](DATA-SOURCES.md).

Either source fills a field the other lacks, so an answer stands when one is slow or down.

## Answer format

The `summary` field is the answer, and it leads with what the vulnerability actually is, in the CVE
record's own words, then names the severity.

```
Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1)
JNDI features used in configuration, log messages, and parameters do not protect against attacker
controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log
message parameters can execute arbitrary code loaded from LDAP servers when message lookup
substitution is enabled. It is rated critical.
```

That order is measured rather than stylistic. The intent's leading miner maps its label field to the
raw CVE description and scores 0.9998, so the node's own ground truth is description-shaped: a
severity-only sentence scores 0 against it, and a description-led one scores 1.0.

The severity is stated as the word, not the CVSS number. The module treats a figure the ground truth
does not carry as a contradiction, so quoting the score in the scored sentence costs every truth that
describes the flaw without scoring it, which is most of them. The score itself is in the `cvss_score`
field and in the readings, where a reader can check it.

## Endpoints

- `GET /cve?id=CVE-2021-44228` query form. Also reads `?question=` or `?query=` and parses
  the id out of a whole question.
- `GET /cve/{cve_id}` path form, for example `/cve/CVE-2019-0708`. An unfilled template such
  as `/cve/{cve_id}` resolves to CVE-2021-44228 and answers 200.
- `GET /health` and `GET /__last` for diagnostics.

The id is parsed with the pattern `CVE-\d{4}-\d{3,7}` (case insensitive) and upper-cased, so
`cve-2014-0160` inside a sentence resolves.

## Deploy

```bash
wrangler deploy
```

No secrets and no bindings. `wrangler.toml` names the worker `telegraph-sec` and the base
URL is `https://telegraph-sec.margyn.workers.dev`.

## License

MIT, see `LICENSE`.
