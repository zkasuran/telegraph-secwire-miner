# Data sources

Every figure this miner serves is a live read at request time. This file records, per source,
what it provides, what its own terms say about commercial use and redistribution, what credit it
requires and what its real rate limit is.

Two rules were followed in writing it. A licence is only recorded when the provider's own terms
page was read; where a page could not be read, that is stated as unverified rather than guessed.
And every source was called from a Cloudflare Worker before it went in, because several hosts
answer differently from a worker than from a laptop.

| Host | Provides | Licence | Commercial use | Attribution | Rate limit |
| --- | --- | --- | --- | --- | --- |
| cve.circl.lu | CVE records: description, CVSS, CWE, affected products | CC BY 4.0 for the CVE Program data underneath. | Permitted by CC BY 4.0 for the CVE data. The instance itself states no licence, which is recorded as unverified. | Credited in every answer. | 20 requests per minute anonymous. |
| services.nvd.nist.gov | Canonical CVSS scores and vectors | No SPDX id. NIST publications are not subject to copyright in the United States. | Permitted. | Required, in that exact wording. | 5 requests in a rolling 30 second window without a key. |

## Per source

### cve.circl.lu

CVE records: description, CVSS, CWE, affected products.

Commercial use: Permitted by CC BY 4.0 for the CVE data. The instance itself states no licence, which is recorded as unverified.

Attribution: Credited in every answer.

Credit line published in every answer:

    CVE data from CIRCL (cve.circl.lu) and the CVE Program, CC BY 4.0.

Rate limit: 20 requests per minute anonymous.

The instance asks automated clients to send a User-Agent with a contact, which the worker now does.

### services.nvd.nist.gov

Canonical CVSS scores and vectors.

What the terms say: The terms ask that "This product uses the NVD API but is not endorsed or certified by the NVD." appear prominently within the application.

Commercial use: Permitted.

Attribution: Required, in that exact wording.

Credit line published in every answer:

    This product uses the NVD API but is not endorsed or certified by the NVD.

Rate limit: 5 requests in a rolling 30 second window without a key.

OPEN ITEM: the declared rate must stay inside 5 per 30 seconds. The descriptor now declares 2 per second, which still exceeds it under sustained load, so the miner races CIRCL first and treats NVD as the corroborating read.

## Compliance

Met:

- cve.circl.lu: the required credit line travels in every answer and in NOTICE.
- services.nvd.nist.gov: the required credit line travels in every answer and in NOTICE.

Open, stated rather than hidden:

- services.nvd.nist.gov: OPEN ITEM: the declared rate must stay inside 5 per 30 seconds. The descriptor now declares 2 per second, which still exceeds it under sustained load, so the miner races CIRCL first and treats NVD as the corroborating read.
