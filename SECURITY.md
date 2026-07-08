# Security Policy

Certheim is a certificate-lifecycle-management product that handles signing
credentials and issued certificates. We take security reports seriously and aim
to respond quickly.

## Reporting a vulnerability

**Email:** security@ac2certinel.com

If you believe the report is sensitive, request our PGP key in your first
message and we will provide one for encrypted follow-up.

Please include, to the extent you can:

- The Certheim **edition and version** (`/api/health` reports the version; the
  admin **Support bundle** — Administration → Overview → *Download support
  bundle* — captures version, edition, and environment with secrets redacted).
- The deployment shape (VM, container, or Kubernetes; SQLite or Postgres).
- Steps to reproduce, a proof-of-concept, and the impact you believe it has.
- Whether the issue is already public.

Please do **not** open a public issue for a suspected vulnerability, and do not
include real private keys, license blobs, or production secrets in your report.

## Our commitment (target timelines)

| Stage | Target |
|---|---|
| Acknowledge receipt | within **3 business days** |
| Initial assessment + severity (CVSS v3.1) | within **10 business days** |
| Fix or documented mitigation for **critical/high** | within **30 days** of confirmation |
| Fix or mitigation for **medium/low** | next scheduled release |

We will keep you informed through triage and remediation, and we credit
reporters in the release notes unless you ask us not to.

## Coordinated disclosure

We ask for coordinated disclosure: give us a reasonable window (target **90
days**, or sooner once a fix ships) before publishing details. For confirmed
vulnerabilities we will request a **CVE** and publish an advisory with the fixed
versions and any workarounds.

## Safe harbor

We will not pursue or support legal action against researchers who, in good
faith:

- test only against **their own** installation of Certheim (never a customer's
  instance, and never our licensing/download infrastructure without written
  permission),
- avoid privacy violations, data destruction, and service degradation,
- do not exfiltrate data beyond the minimum needed to prove a finding, and
- give us a reasonable time to remediate before public disclosure.

Activity consistent with this policy is considered authorized. If in doubt about
whether something is in scope, ask first at security@ac2certinel.com.

## Scope

**In scope** — the Certheim application (all editions), its container images and
release artifacts, the install/upgrade tooling, and the licensing/verification
mechanisms as shipped.

**Out of scope** — third-party CA backends (OpenBao, AD CS, EJBCA, Venafi, AWS
PCA, HSMs, etc.), the host OS and its crypto module, denial-of-service via
volumetric traffic, findings that require a pre-compromised host or a malicious
administrator, and social engineering.

## Verifying what you run

Every Certheim container image is published with an **SBOM and SLSA provenance
attestation**, and tarball releases ship with checksums. Before trusting a
build, verify it — see [`docs/verifying-releases.md`](docs/verifying-releases.md).
