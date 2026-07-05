# Verifying Certinel releases

Certinel ships two kinds of artifact, and both can be verified before you trust
them:

- **Container images** — published with an in-toto **SBOM** and a **SLSA
  provenance** attestation (BuildKit `mode=max`).
- **Offline tarball bundles** (Community download) — published with a
  **SHA-256** checksum recorded in the download manifest.

Verifying is optional but recommended, especially before an air-gapped or
regulated deployment.

---

## Container images

Public images live at `docker.io/ac2solutions/certinel` (Commercial/Government
customers also pull the same attested images from the entitled registry
`registry.ac2certinel.com/certinel`). Tags:

- `:<edition>-vX.Y.Z` — immutable, one per release (e.g. `commercial-v3.72.0`)
- `:<edition>-latest` — moving pointer to the newest release of that edition
- `:latest` / `:slim` — newest Community (UBI9 / python-slim base)

**Always pin the immutable `:<edition>-vX.Y.Z` tag for a verified deployment** —
a moving tag can advance under you between the check and the pull.

### 1. Inspect the attestations

With Docker Buildx (no extra tooling):

```bash
docker buildx imagetools inspect \
  docker.io/ac2solutions/certinel:commercial-v3.72.0 \
  --format '{{ json .SBOM }}'          # software bill of materials

docker buildx imagetools inspect \
  docker.io/ac2solutions/certinel:commercial-v3.72.0 \
  --format '{{ json .Provenance }}'    # SLSA build provenance (source, builder)
```

The provenance records the source repository/commit the image was built from and
the builder identity; the SBOM lists every OS and Python package in the image so
you can diff it against your CVE feed.

### 2. Verify with cosign (optional, scriptable)

```bash
# the SBOM attestation
cosign verify-attestation --type spdxjson \
  docker.io/ac2solutions/certinel:commercial-v3.72.0

# the SLSA provenance attestation
cosign verify-attestation --type slsaprovenance \
  docker.io/ac2solutions/certinel:commercial-v3.72.0
```

### 3. Pin by digest

Once you trust a tag, resolve and deploy by digest so the running image can
never silently change:

```bash
docker buildx imagetools inspect \
  docker.io/ac2solutions/certinel:commercial-v3.72.0 --format '{{ .Manifest.Digest }}'
# -> sha256:...

# then deploy   ...certinel@sha256:...
```

> **Note:** if `imagetools inspect` reports no SBOM/provenance, the image was
> built by the buildah fallback path (BuildKit unavailable on the runner at
> build time) rather than the attested path. Prefer a tag whose attestations are
> present, or contact support@ac2certinel.com.

---

## Offline tarball bundles (Community)

Each Community download is a `certinel-offline-<version>.tar.gz` whose SHA-256 is
recorded in the download manifest served alongside it.

```bash
sha256sum certinel-offline-<version>.tar.gz
# compare against the "sha256" field shown on the download page / manifest
```

A mismatch means the file was truncated, tampered with, or corrupted in
transit — do not install it; re-download and report a persistent mismatch to
security@ac2certinel.com.

---

## License blobs

Certinel licenses are **offline-verifiable**: the application checks an RSA
signature over the license payload against a bundled public key, with no
phone-home. A tampered or expired license is rejected at load; see the
Administration → License page for the active license's status and expiry.
