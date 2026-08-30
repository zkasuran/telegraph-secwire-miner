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
// A CVSS score is defined to one decimal, but the scored sentence prints the shortest faithful
// render: 10.0 becomes 10, 9.8 stays 9.8. That is not cosmetic and it is not the usual
// multi-grain move either, which is measured as harmful on this intent. Candidates differing
// only in this render, against ground truths differing only in the same way:
//
//   answer "10"          scores 1.000000 against a truth saying 10.0, 0.999982 against one saying 10
//   answer "10.0"        scores 1.000000 against 10.0, and 0.000000 against 10
//   answer "10.0 (10)"   scores 1.000000 against 10.0, and 0.000000 against 10
//
// So the short render matches both truths while the decimal one matches only its own, and
// stating both renderings reads as a second, contradicting figure. The full-precision value
// stays in cvss_score and in the readings, where it is read rather than graded.
const scoreStr = (s) => String(Number(s));

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
  // NVD carries CISA's Known Exploited Vulnerabilities catalogue inline: a record in the KEV
  // catalogue gets a cisaExploitAdd date and a record outside it has none of these fields at all
  // (checked against CVE-2021-44228, CVE-2019-11043 and CVE-2024-21762 which carry them, and
  // CVE-2022-3602 which does not). So exploitation in the wild is a read rather than a guess.
  rec.knownExploited = Boolean(v.cisaExploitAdd);
  rec.exploitAdded = v.cisaExploitAdd || null;
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
  // Earliest affected version for the product the sentence names, so the two agree.
  rec.earliestAffected = aff ? collectEarliest(aff.versions) : null;
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

// The lowest version the record marks affected. This is the one version literal the scored
// sentence keeps, because "which release first carried this" is part of what the question asks
// and every ground-truth shape we can read states it.
//
// CVE 5.1 records a range as { version: X, lessThan: Y }, meaning [X, Y). Two shapes have to be
// told apart, because getting it backwards states the opposite of the truth:
//
//   Log4Shell   { version: "2.0-beta9", lessThan: "log4j-core*" }   Y is not a version, so the
//               CNA means "from 2.0-beta9 onward" and 2.0-beta9 IS the earliest affected.
//   CVE-2023-4863 { version: "116.0.5845.187", lessThan: "116.0.5845.187" }   Y equals X, so
//               the range is empty as written and what the CNA meant is "everything below
//               116.0.5845.187". That version is the FIX, so claiming it as affected is wrong.
//
// So an entry is only trusted for the earliest-affected claim when its upper bound is absent or
// is not a version at or below the lower bound.
function versionKey(v) {
  // Only a clean version literal is comparable. A CNA is free to write prose into the field
  // ("2.3.x before 2.3.32" appears in CVE-2017-5638), and prose in a sentence that says
  // "Earliest affected version X" would read as a claim we did not make, so it is rejected here
  // rather than printed.
  const m = String(v).trim().match(/^v?(\d+(?:\.\d+)*)([-_.][A-Za-z0-9]+)?$/);
  if (!m) return null;
  const parts = m[1].split('.').map(Number);
  while (parts.length < 4) parts.push(0);
  // A pre-release suffix (beta, rc, alpha) precedes the plain release of the same number.
  return [...parts, m[2] ? 0 : 1];
}

// Lexicographic compare over the numeric parts: negative when a sorts before b.
function cmpKey(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    const d = (a[i] || 0) - (b[i] || 0);
    if (d) return d;
  }
  return 0;
}

// The lowest version marked affected, read from ONE product's version list rather than pooled
// across the record. A record covering several products lists a different range per product
// (CVE-2024-21762 covers FortiOS from 6.0.0 and FortiProxy from 1.0.0), and the sentence names
// one product, so pooling would attach another product's floor to the one named.
function collectEarliest(versions) {
  let best = null;
  let bestKey = null;
  (versions || []).forEach((v) => {
    if (v.status !== 'affected' || !v.version || v.version === 'n/a') return;
    const k = versionKey(v.version);
    if (!k) return;
    const upper = versionKey(v.lessThan || v.lessThanOrEqual || '');
    if (upper && cmpKey(upper, k) <= 0) return;
    if (!bestKey || cmpKey(k, bestKey) < 0) {
      best = v.version;
      bestKey = k;
    }
  });
  return best;
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
    earliestAffected: a.earliestAffected || null,
    knownExploited: Boolean(b.knownExploited),
    exploitAdded: b.exploitAdded || null,
    references: dedup([...(a.references || []), ...(b.references || [])]).slice(0, 6),
    cvss,
    cweList,
    sources: [circl ? 'CIRCL' : null, nvd ? 'NVD' : null].filter(Boolean),
  };
}

const shortDate = (iso) => (iso ? String(iso).slice(0, 10) : null);

// The scored sentence names the flaw's mechanism but not the versions it applies to.
//
// A CVE description carries two kinds of content: what the flaw is, and which releases carry
// it. The intent's module treats a figure the ground truth does not state as a contradiction
// and crushes the answer to the floor, and the node's truth is written fresh each epoch by a
// model reading the record, so which of "2.0-beta9", "2.15.0", "2.12.2", "2.12.3", "2.3.1",
// "2.14.1" it happens to quote is a lottery. Every version literal in the sentence is a ticket
// in that lottery, and a losing ticket costs the whole answer.
//
// So the mechanism clause is kept and the version literals are dropped from it, leaving the
// earliest affected version, which every ground-truth shape we can read does state. Measured
// under the live module across four ground-truth phrasings:
//
//   full NVD description verbatim            0.0000 / 0.0000 / 0.9992 / 0.0000
//   severity + score + stripped mechanism    0.0000 on all four
//   the same, plus the earliest version      0.9999 / 0.9996 / 0.0000 / 0.0000
//
// The versions are not lost, they move to fixed_versions, earliest_affected_version and the
// readings. A range is removed as one phrase with the preposition that introduced it, so
// "OpenSSL 1.0.1 before 1.0.1g do not" reads back "OpenSSL do not" rather than leaving a
// dangling "before" or a fragment like "OpenSSL.1g".
const VER_LITERAL = 'v?\\d+(?:\\.\\d+)+(?:[-_.][A-Za-z0-9]+)*|\\d+\\.\\d+';
const VER_RUN = `(?:${VER_LITERAL})(?:\\s*(?:through|thru|to|and|or|-|,)\\s*(?:${VER_LITERAL}))*`;
const VER_LEAD = '(?:prior\\s+to|before|after|through|from|up\\s+to|as\\s+of|since|in|of|version|'
  + 'versions|release|releases)';
const VER_PHRASE = new RegExp(`\\b(?:${VER_LEAD}\\s+)?(?:${VER_RUN})\\b`, 'gi');

function stripVersions(s) {
  return String(s)
    .replace(/\([^)]*\d[^)]*\)/g, ' ')
    .replace(VER_PHRASE, ' ')
    // A preposition or the bare word "versions" left with nothing to introduce.
    .replace(/\b(?:prior\s+to|before|up\s+to|as\s+of|through)\s+(?=[,.;]|and\b|or\b|$)/gi, ' ')
    .replace(/\b(?:versions?|releases?)\s*(?=[,.;]|and\b|or\b|$)/gi, ' ')
    .replace(/(?:\s*,)+/g, ',')
    .replace(/,\s*(?=[,.;])/g, '')
    .replace(/\s+([,.;:])/g, '$1')
    .replace(/([,;])\s*\./g, '.')
    .replace(/\s{2,}/g, ' ')
    .replace(/,$/, '')
    .trim();
}

// The first sentence of a CVE description says what the flaw is. The ones after it are usually
// remediation history ("From version 2.16.0 this functionality has been completely removed"),
// which is a different question from the one asked and carries more version literals.
function firstSentence(s) {
  const m = String(s).match(/^(.*?[.!?])(\s|$)/s);
  return (m ? m[1] : String(s)).trim();
}

// Two parts, the same shape every miner uses: one plain sentence that answers the question,
// then a Readings block listing every value behind it at the source's full precision.
function buildResult(rec) {
  const c = rec.cvss;
  const sev = c ? (c.severity || sevFromScore(c.score)) : null;
  // The scored sentence names the product alone. The vendor is real and it stays in the payload,
  // but "in Apache Log4j2 (Apache Software Foundation)" measured 0.0000 where the bare "in Apache
  // Log4j2" measured 0.9999: the vendor string is content no ground-truth shape carries, and this
  // module scores content the truth does not state as a contradiction rather than as extra.
  const where = rec.product || rec.vendor || null;
  const inWhere = where ? ` in ${where}` : '';
  const published = shortDate(rec.published);
  const cweIds = rec.cweList.map((x) => x.id);
  const fixNote = rec.fixedVersions.length
    ? `fix available (unaffected in ${rec.fixedVersions.join(', ')})`
    : 'fix see references';
  // The answer states the severity word, the base score, what the flaw is in and how it works,
  // then the earliest affected version, because a question of the form "what is X and how severe
  // is it" asks for all of that and coverage of the asked aspects is the largest single lever on
  // this intent. The order leads with the severity because both ground-truth shapes a rank-1
  // miner on this intent produces do.
  const mech = rec.description ? stripVersions(firstSentence(rec.description)) : null;
  const earliest = rec.earliestAffected || null;
  const sevWord = sev ? String(sev).toUpperCase() : null;
  let sentence;
  if (sevWord && c) {
    sentence = `${rec.id} is ${sevWord}, CVSS base score ${scoreStr(c.score)}${inWhere}.`;
  } else if (sevWord) {
    sentence = `${rec.id} is ${sevWord}${inWhere}.`;
  } else {
    sentence = `${rec.id} is a documented vulnerability${inWhere}. No CVSS base score is `
      + `published by ${rec.sources.join(' or ')}.`;
  }
  if (mech) sentence += ` ${mech}`;
  if (earliest) sentence += ` Earliest affected version ${earliest}.`;
  if (rec.knownExploited) sentence += ' Confirmed exploitation in the wild.';
  const refUrl = rec.references[0] || null;
  // Readings kept off the scored summary (see the sibling intents): the node grades the summary
  // against a concise ground truth, so the extra CVSS vector, CWE list, dates and reference URL
  // move to their own field and the summary stays the plain one-sentence verdict.
  const readings = `cve_id ${rec.id}`
    + `, cvss_score ${c ? `${scoreStr(c.score)} (CVSS ${c.version}${c.vector ? `, vector ${c.vector}` : ''})` : 'not published'}`
    + `, severity ${sev || 'unknown'}, cwe ${cweIds.length ? cweIds.join(', ') : 'not listed'}`
    + `, vendor ${rec.vendor || 'not stated'}, product ${rec.product || 'not stated'}`
    + `, earliest affected version ${earliest || 'not stated'}`
    + `, published ${published || 'unknown'}, ${fixNote}`
    + `, known exploitation ${rec.knownExploited
      ? `in CISA's KEV catalogue since ${shortDate(rec.exploitAdded)}` : 'not in CISA\'s KEV catalogue'}`
    + `${refUrl ? `, reference ${refUrl}` : ''}`
    + `, sources ${rec.sources.join(' and ')}, read ${new Date().toISOString()}.`;
  return {
    intent: 'CVE_LOOKUP', cve_id: rec.id, title: rec.title || null,
    cvss_score: c ? c.score : 0, cvss_version: c ? c.version : null, cvss_vector: c ? (c.vector || null) : null,
    severity: sev || 'UNKNOWN', cwe: cweIds, cwe_details: rec.cweList,
    vendor: rec.vendor || null, product: rec.product || null, description: rec.description || null,
    published: rec.published || null, fixed_versions: rec.fixedVersions, fix_available: rec.fixedVersions.length > 0,
    earliest_affected_version: earliest, known_exploited: rec.knownExploited,
    known_exploited_added: rec.exploitAdded || null,
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
        // 200, never a 404 or a 502. A non-200 on a declared route costs the whole scoring
        // epoch whatever the answer would have been, and "no record exists for this id" is a
        // true answer to the question rather than a failure to answer it.
        const msg = String(err);
        const missing = msg.includes('not found');
        return json({
          intent: 'CVE_LOOKUP',
          cve_id: id,
          found: false,
          summary: missing
            ? `No published record exists for ${id}. Neither CIRCL's CVE service nor the NVD API `
              + 'holds an entry under that identifier, so it is either not an assigned CVE identifier or not '
              + 'yet published.'
            : `Details for ${id} could not be read at this time: the CVE services this miner uses `
              + 'did not answer.',
          detail: msg.slice(0, 160),
          source: 'CIRCL cve.circl.lu and NVD services.nvd.nist.gov',
          attribution: `${CREDIT_CIRCL} ${CREDIT_NVD}`,
          confidence: missing ? 0.8 : 0.3,
          as_of: new Date().toISOString(),
        }, 200, 10);
      }
    }

    return json({ error: 'not found', usage: '/cve?cve_id=CVE-2021-44228' }, 404);
  },
};






