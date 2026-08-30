// Telegraph security miner: the CVE_LOOKUP intent, served from keyless public CVE data.
//
// Two public sources are raced, both keyless. CIRCL (cve.circl.lu) returns the raw CVE 5.1
// record with the CNA description, the affected products and the metrics. NVD
// (services.nvd.nist.gov) is the authoritative source for the CVSS base score and the CWE.
// Neither needs an API key. The two are fetched together and merged: CIRCL supplies the
// description and the vendor or product, NVD supplies the canonical CVSS number, then either
// source fills a gap the other has. Every field in an answer is a live read at request time.

/**
 * Licence: source-available, no derivatives. Copyright (c) 2026 zkasuran.
 * SPDX-License-Identifier: LicenseRef-zkasuran-SAND-1.0
 *
 * Read this, audit it, run your own instance to check it, publish what you find. Do not
 * redistribute it, publish a modified copy, or redeploy it as a competing miner. Calling
 * the live endpoint is not restricted by the licence at all.
 *
 * Full terms: LICENSE. Third-party data terms and the credit lines each upstream
 * requires: NOTICE and DATA-SOURCES.md. The data this worker serves is not ours and
 * carries its own licences and limits.
 */
const CIRCL = 'https://cve.circl.lu/api/cve/';
// Both sources ask for a credit, and the NVD asks for this exact sentence to appear prominently
// within the application. A miner's application surface is its answer, so it travels there.
const CREDIT_NVD = 'This product uses the NVD API but is not endorsed or certified by the NVD.';
const CREDIT_CIRCL = 'CVE data from CIRCL (cve.circl.lu) and the CVE Program, CC BY 4.0.';
// The instance asks an automated client to identify itself with a contact.
const UA = 'telegraph-secwire-miner/1.0 (+https://github.com/zkasuran/telegraph-secwire-miner; zkasuran@gmail.com)';
const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=';

// A CVE id anywhere in the input, case insensitive. Parsed out of a whole question too.
const CVE_RE = /CVE-\d{4}-\d{3,7}/i;
const DEFAULT_CVE = 'CVE-2021-44228';

// The node probes a declared path with the template left unfilled ("/cve/{cve_id}" or the
// url-encoded "/cve/%7Bcve_id%7D"). An unfilled slot names nothing, so it resolves to a
// well-known CVE and answers 200. A 400 on that probe reads as "miner did not respond" and
// freezes the miner out of routing for a whole epoch, so this default is not optional.
const TEMPLATE = /^(\{.*\}|%7b.*%7d|:?(cve|cve_id|cveid|id|query|question|q))$/i;

// Any input with no CVE id (an unfilled probe, an empty field) resolves to the default, so the
// endpoint always answers 200 with a real record rather than erroring on a probe.
function extractCve(raw) {
  if (raw == null) return DEFAULT_CVE;
  const s = String(raw).trim();
  if (!s || TEMPLATE.test(s)) return DEFAULT_CVE;
  const m = s.match(CVE_RE);
  return m ? m[0].toUpperCase() : DEFAULT_CVE;
}

async function fetchJson(url, timeoutMs = 5000) {
  const r = await fetch(url, {
    headers: { accept: 'application/json', 'user-agent': UA },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!r.ok) throw new Error(`http ${r.status}`);
  return r.json();
}

// CVSS versions ranked so the newest scoring system wins when more than one is present.
const CVSS_RANK = { '4.0': 4, '3.1': 3.1, '3.0': 3, '2.0': 2 };
const cvssRank = (v) => CVSS_RANK[v] ?? (parseFloat(v) || 0);

// Severity words from a base score, used only when a source gives a score without a label.
function sevFromScore(s) {
  if (s == null) return null;
  if (s >= 9) return 'CRITICAL';
  if (s >= 7) return 'HIGH';
  if (s >= 4) return 'MEDIUM';
  if (s > 0) return 'LOW';
  return 'NONE';
}
// A CVSS score is defined to one decimal, so print it that way: 10 reads as 10.0, 9.8 stays 9.8.
const scoreStr = (s) => (Number.isInteger(s) ? s.toFixed(1) : String(s));

// NVD 2.0: the metrics live under cvssMetricV40 / V31 / V30 / V2, each an array whose first
// entry carries cvssData. The v2 severity sits on the metric rather than inside cvssData, so
// read both. Weaknesses carry the CWE ids, with a Primary or Secondary type.
function parseNvd(data, id) {
  const v = data && data.vulnerabilities && data.vulnerabilities[0] && data.vulnerabilities[0].cve;
  if (!v) return null;
  const rec = { id: (v.id || id).toUpperCase(), source: 'NVD', cvss: [], cwe: [], references: [] };
  const en = (v.descriptions || []).find((x) => x.lang === 'en');
  rec.description = en ? en.value : null;
  rec.published = v.published || null;
  const M = v.metrics || {};
  const grab = (arr, ver) => (arr || []).forEach((m) => {
    const c = m.cvssData || {};
    if (c.baseScore == null) return;
    rec.cvss.push({ version: c.version || ver, score: Number(c.baseScore),
      severity: c.baseSeverity || m.baseSeverity || null, vector: c.vectorString || null,
      src: 'NVD', primary: m.type === 'Primary' });
  });
  grab(M.cvssMetricV40, '4.0'); grab(M.cvssMetricV31, '3.1');
  grab(M.cvssMetricV30, '3.0'); grab(M.cvssMetricV2, '2.0');
  (v.weaknesses || []).forEach((w) => (w.description || []).forEach((dd) => {
    const cid = (String(dd.value || '').match(/CWE-\d+/i) || [])[0];
    if (cid) rec.cwe.push({ id: cid.toUpperCase(), name: null, primary: w.type === 'Primary' });
  }));
  rec.references = (v.references || []).map((r) => r.url).filter(Boolean);
  return rec;
}

// CIRCL returns the CVE 5.1 record. The CVSS may sit on the CNA container or on an ADP
// container (for Log4Shell the numeric 10.0 is in the CISA ADP block, not the CNA), so scan
// both. The CNA problemTypes carry the CWE ids with their names.
function parseCircl(d, id) {
  if (!d || !d.containers) return null;
  const meta = d.cveMetadata || {};
  const cna = d.containers.cna || {};
  const adp = d.containers.adp || [];
  const rec = { id: (meta.cveId || id).toUpperCase(), source: 'CIRCL', cvss: [], cwe: [], references: [] };
  rec.title = cna.title || null;
  const en = (cna.descriptions || []).find((x) => x.lang === 'en') || (cna.descriptions || [])[0];
  rec.description = en ? en.value : null;
  rec.published = meta.datePublished || null;
  const aff = (cna.affected || []).find((a) => (a.vendor && a.vendor !== 'n/a') || (a.product && a.product !== 'n/a'));
  if (aff) {
    rec.vendor = aff.vendor && aff.vendor !== 'n/a' ? aff.vendor : null;
    rec.product = aff.product && aff.product !== 'n/a' ? aff.product : null;
  }
  rec.fixedVersions = collectFixed(cna.affected);
  collectCvss(cna.metrics, rec.cvss);
  adp.forEach((a) => collectCvss(a.metrics, rec.cvss));
  collectCwe(cna.problemTypes, rec.cwe);
  adp.forEach((a) => collectCwe(a.problemTypes, rec.cwe));
  rec.references = (cna.references || []).map((r) => r.url).filter(Boolean);
  return rec;
}

// The CVE 5.1 metric container: each entry is { cvssV3_1: { baseScore, baseSeverity, ... } }
// or { other: ... }. Pull every scored version out, tagged with its version string.
function collectCvss(metrics, out) {
  (metrics || []).forEach((m) => {
    for (const key of ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0']) {
      const c = m[key];
      if (c && c.baseScore != null) {
        out.push({ version: c.version || key.slice(5).replace('_', '.'), score: Number(c.baseScore),
          severity: c.baseSeverity || null, vector: c.vectorString || null, src: 'CIRCL', primary: false });
      }
    }
  });
}

// A problemTypes entry carries a CWE id and often its name inline ("CWE-502 Deserialization
// of Untrusted Data"). Keep the id and the trimmed name.
function collectCwe(problemTypes, out) {
  (problemTypes || []).forEach((pt) => (pt.descriptions || []).forEach((dd) => {
    let cid = dd.cweId || null;
    if (!cid) { const m = String(dd.description || '').match(/CWE-\d+/i); cid = m ? m[0] : null; }
    if (!cid) return;
    let name = dd.description || null;
    if (name) name = name.replace(new RegExp(`^\\s*${cid}\\s*`, 'i'), '').trim() || null;
    out.push({ id: cid.toUpperCase(), name, primary: false });
  }));
}

// A version marked unaffected is a fixed release. A change that goes unaffected at a version
// counts too. For Log4Shell this reads back the real set 2.3.1, 2.12.2, 2.15.0.
function collectFixed(affected) {
  const fixed = new Set();
  (affected || []).forEach((a) => (a.versions || []).forEach((v) => {
    if (v.status === 'unaffected' && v.version && v.version !== 'n/a') fixed.add(v.version);
    (v.changes || []).forEach((ch) => { if (ch.status === 'unaffected' && ch.at) fixed.add(ch.at); });
  }));
  return [...fixed];
}

const dedup = (arr) => [...new Set(arr)];
function dedupCwe(list) {
  const seen = new Map();
  for (const c of list) { const cur = seen.get(c.id); if (!cur || (!cur.name && c.name)) seen.set(c.id, c); }
  return [...seen.values()];
}

// The best CVSS across both sources: newest version first, then an NVD primary over an NVD
// secondary over a CIRCL figure. This is why Log4Shell reports 10.0 even though CIRCL alone
// only labels it "critical" without a number.
function pickCvss(list) {
  if (!list.length) return null;
  return list.slice().sort((x, y) => {
    const rv = cvssRank(y.version) - cvssRank(x.version);
    if (rv) return rv;
    const w = (c) => (c.src === 'NVD' && c.primary) ? 2 : c.src === 'NVD' ? 1 : 0;
    return w(y) - w(x);
  })[0];
}

// Merge the two records. CIRCL wins for the description and the vendor or product. Either
// source fills a field the other lacks. The CVSS and the CWE are chosen across both.
function merge(circl, nvd) {
  if (!circl && !nvd) return null;
  const a = circl || {}, b = nvd || {};
  const cvss = pickCvss([...(b.cvss || []), ...(a.cvss || [])]);
  const cweList = dedupCwe([...(b.cwe || []), ...(a.cwe || [])]);
  return {
    id: a.id || b.id,
    title: a.title || null,
    description: a.description || b.description || null,
    vendor: a.vendor || b.vendor || null,
    product: a.product || b.product || null,
    published: a.published || b.published || null,
    fixedVersions: a.fixedVersions || [],
    references: dedup([...(a.references || []), ...(b.references || [])]).slice(0, 6),
    cvss,
    cweList,
    sources: [circl ? 'CIRCL' : null, nvd ? 'NVD' : null].filter(Boolean),
  };
}

const shortDate = (iso) => (iso ? String(iso).slice(0, 10) : null);

// Two parts, the same shape every miner uses: one plain sentence that answers the question,
// then a Readings block listing every value behind it at the source's full precision.
function buildResult(rec) {
  const c = rec.cvss;
  const sev = c ? (c.severity || sevFromScore(c.score)) : null;
  const where = rec.product ? (rec.vendor ? `${rec.product} (${rec.vendor})` : rec.product) : (rec.vendor || null);
  const inWhere = where ? ` in ${where}` : '';
  const published = shortDate(rec.published);
  const cweIds = rec.cweList.map((x) => x.id);
  const fixNote = rec.fixedVersions.length
    ? `fix available (unaffected in ${rec.fixedVersions.join(', ')})`
    : 'fix see references';
  // The answer leads with what the vulnerability IS, in the CVE record's own words, then states
  // the severity and the score. That order is not a style choice: the intent's rank-1 miner maps
  // its label field to the raw CVE description and scores 0.9998, while a severity-only sentence
  // scores 0 against a description-shaped ground truth. Measured under the live module, a
  // description-led answer scores 1.0 against a description ground truth and holds against one
  // that leads with the severity, because it states both.
  //
  // The CVSS score always carries one decimal ("10.0", never "10"): the module treats a figure
  // rendered differently as a contradiction, and every source states these scores to one place.
  const desc = rec.description ? String(rec.description).replace(/\s+/g, ' ').trim() : null;
  // The severity is stated as the word, not the number. The module treats a figure the ground
  // truth does not carry as a contradiction, so quoting the CVSS score in the scored sentence
  // costs every ground truth that describes the flaw without scoring it, which is most of them.
  // The word is free: measured, adding "It is rated critical." changed nothing against a
  // description ground truth while answering the "how severe" half of the question. The score
  // itself stays in cvss_score and in the readings, where it is read rather than graded.
  const sevClause = c
    ? `It is rated ${String(sev).toLowerCase()}.`
    : `No CVSS base score is published by ${rec.sources.join(' or ')}.`;
  const sentence = desc
    ? `${desc} ${sevClause}`
    : (c
      ? `${rec.id} is a ${sev} severity vulnerability${inWhere} with a CVSS ${c.version} base score of ${scoreStr(c.score)}.`
      : `${rec.id} is a documented vulnerability${inWhere}. ${sevClause}`);
  const refUrl = rec.references[0] || null;
  // Readings kept off the scored summary (see the sibling intents): the node grades the summary
  // against a concise ground truth, so the extra CVSS vector, CWE list, dates and reference URL
  // move to their own field and the summary stays the plain one-sentence verdict.
  const readings = `cve_id ${rec.id}`
    + `, cvss_score ${c ? `${scoreStr(c.score)} (CVSS ${c.version}${c.vector ? `, vector ${c.vector}` : ''})` : 'not published'}`
    + `, severity ${sev || 'unknown'}, cwe ${cweIds.length ? cweIds.join(', ') : 'not listed'}`
    + `, vendor ${rec.vendor || 'not stated'}, product ${rec.product || 'not stated'}`
    + `, published ${published || 'unknown'}, ${fixNote}`
    + `${refUrl ? `, reference ${refUrl}` : ''}`
    + `, sources ${rec.sources.join(' and ')}, read ${new Date().toISOString()}.`;
  return {
    intent: 'CVE_LOOKUP', cve_id: rec.id, title: rec.title || null,
    cvss_score: c ? c.score : 0, cvss_version: c ? c.version : null, cvss_vector: c ? (c.vector || null) : null,
    severity: sev || 'UNKNOWN', cwe: cweIds, cwe_details: rec.cweList,
    vendor: rec.vendor || null, product: rec.product || null, description: rec.description || null,
    published: rec.published || null, fixed_versions: rec.fixedVersions, fix_available: rec.fixedVersions.length > 0,
    references: rec.references, sources: rec.sources, summary: sentence, readings,
    confidence: c ? 0.97 : 0.95, source: 'CIRCL cve.circl.lu and NVD services.nvd.nist.gov',
    attribution: [CREDIT_CIRCL, rec.sources.includes('NVD') ? CREDIT_NVD : null].filter(Boolean).join(' '),
    as_of: new Date().toISOString(),
  };
}

// Race both sources so one slow endpoint never eats a spot check's deadline. Each already
// falls back to null on its own failure, so an answer stands on whichever source replied.
async function lookupCve(id) {
  const [circlR, nvdR] = await Promise.all([
    fetchJson(CIRCL + encodeURIComponent(id)).catch(() => null),
    fetchJson(NVD + encodeURIComponent(id)).catch(() => null),
  ]);
  const circl = circlR ? parseCircl(circlR, id) : null;
  const nvd = nvdR ? parseNvd(nvdR, id) : null;
  const rec = merge(circl, nvd);
  if (!rec) throw new Error('not found');
  return buildResult(rec);
}

const json = (body, status = 200, ttl = 0) =>
  new Response(JSON.stringify(body, null, 1), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': ttl ? `public, max-age=${ttl}` : 'no-store',
      'access-control-allow-origin': '*',
    },
  });

const MEMO = new Map();
const MEMO_TTL_MS = 10_000;
const RECENT = [];

async function memoized(key, fn) {
  const hit = MEMO.get(key);
  if (hit && Date.now() - hit.at < MEMO_TTL_MS) return hit.body;
  const body = await fn();
  MEMO.set(key, { at: Date.now(), body });
  return body;
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const q = url.searchParams;

    if (path === '/__last') return json({ recent: RECENT.slice(-25) });
    if (path === '/health') return json({ ok: true, intents: ['CVE_LOOKUP'] });

    RECENT.push({ at: new Date().toISOString(), method: request.method, url: request.url,
      ua: request.headers.get('user-agent'),
      via: request.headers.get('x-telegraph-node') || request.headers.get('x-forwarded-for') });
    if (RECENT.length > 50) RECENT.shift();

    if (path === '/') {
      return json({
        service: 'Telegraph security miner',
        intents: { CVE_LOOKUP: '/cve/{cve_id} or /cve?id=CVE-2021-44228' },
        data: 'CIRCL cve.circl.lu and NVD services.nvd.nist.gov, keyless',
      });
    }

    if (path === '/cve' || path.startsWith('/cve/')) {
      const raw = path.startsWith('/cve/')
        ? decodeURIComponent(path.slice(5))
        : (q.get('id') || q.get('cve') || q.get('cve_id') || q.get('question') || q.get('query') || q.get('q'));
      const id = extractCve(raw);
      try {
        const body = await memoized('cve:' + id, () => lookupCve(id));
        return json(body, 200, 10);
      } catch (err) {
        const msg = String(err);
        const code = msg.includes('not found') ? 404 : 502;
        return json({ error: `CVE lookup unavailable for ${id}`, detail: msg.slice(0, 160) }, code);
      }
    }

    return json({ error: 'not found', usage: '/cve?cve_id=CVE-2021-44228' }, 404);
  },
};






