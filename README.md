# kernelscan-dt-plugin

Dependency-Track **v5** plugin shipping KernelScan extensions. First extension:
a **`vuln-data-source`** that mirrors KernelScan's kernel-CVE feed into DT's
vulnerability database — giving DT users a **fast lane for Linux kernel CVEs**
(KernelScan publishes ahead of NVD ~90% of the time) and **richer affected-version
data** than NVD's kernel CPE ranges (per-branch introduced/fixed intervals from
kernel.org / cvelistV5 enrichment).

A `vuln-analyzer` extension (per-project, config-aware — the Snyk/VulnDB slot)
may join later in the same JAR; one `Plugin` can ship multiple extension factories.

## How it plugs in

DT v5 discovers plugins via `ServiceLoader` over the apiserver classpath, which
includes `lib/*` (`-cp 'dependency-track-apiserver.jar:lib/*'`). Deployment is:

```yaml
# docker-compose.yml, apiserver service
volumes:
  - ./plugins/kernelscan-dt-plugin.jar:/opt/owasp/dependency-track/lib/kernelscan-dt-plugin.jar:ro
```

The data source then appears under **Administration → Vulnerability Sources**
(extension point `vuln-data-source`, next to nvd/osv/github) with its own
config form (feed URL + feed token), rendered from the JSON schema in
`src/main/resources/.../kernel-scan-vuln-data-source-config-v1.schema.json`.

The 3 built-in sources load through the *identical* mechanism
(`vuln-data-source/{nvd,osv,github}` modules upstream) — there is no
privileged core path. Proven end-to-end with a hello-world analyzer on the m2
testbed 2026-07-05 (`kernelscan-ops/dtrack-test/plugin-hello/`).

## Design

### Contract

`VulnDataSource extends ExtensionPoint, Iterator<Bom>` — an iterator over
CycloneDX **BOVs** (Bill of Vulnerabilities, protobuf `org.cyclonedx.proto.v1_7`).
DT's `MirrorVulnDataSourceActivity` drains the iterator and calls
`markProcessed(bov)` after durably storing each BOV — that's the watermark ack
for incremental mirroring (watermark persisted in the plugin `KeyValueStore`,
ADR-012).

### Identity: plain CVE ids, source NVD (the crux)

Each emitted BOV carries `vulnerabilities[].id = CVE-*` with
`source = {name: "NVD"}` — **not** a KernelScan-namespaced id:

- **Fastlane:** a kernel CVE KernelScan publishes before NVD gets created in
  DT's DB under its *final* identity. When NVD later publishes, its mirror
  updates the *same record* (temporal update guard: incoming `updated` must be
  strictly newer). No identity churn, no INTERNAL→NVD migration, no aliases.
- **Enrichment:** for CVEs NVD already has, our record contributes per-branch
  affected ranges (`vers:generic/>=introduced|<fixed` per kernel series) that
  are strictly better than NVD's kernel CPE matching.
- The 4.x OSV-mirror approach (KSCAN-* ids + aliases) is the proven dead end:
  DT links aliases but never propagates analysis across them, and duplicate
  findings result. See kernelscan-ops#65 for the full post-mortem.

**Open question #1 (validate empirically, slice 2):** DT's sync ownership
guards — analyzers may only update vulns whose source they're authoritative
for, *or* whose mirroring is disabled. Whether a `vuln-data-source` BOV with
`source=NVD` (from extension `kernelscan`) updates an existing NVD-mirror-owned
row while NVD mirroring is enabled needs a live test. Outcomes:
  - *Updates win (timestamp-guarded):* enrichment works as designed; expect
    benign ping-pong with NVD re-imports — verify convergence.
  - *Blocked:* fastlane still works (records NVD doesn't have yet are created
    by us and handed over on NVD publication); enrichment of existing rows
    would need either NVD-mirroring-off for kernel CVEs, or an upstream
    conversation about per-source field-level merge.

### Feed side

Polls KernelScan's tokenized CycloneDX feed (plain CVE ids, all kernel CVEs):

```
GET {feedBaseUrl}/t/{feedToken}/cyclonedx/all.json
```

Incremental sync is client-side for now: filter records by `updated` >
watermark; commit watermark once the run drains. **Backend follow-up:** a
`?since=` parameter on the feed endpoint for true server-side increments
(the full corpus is ~50k records / tens of MB).

### BOV shape (per CVE)

```
components:      [ { bom-ref: "linux-kernel", type: OPERATING_SYSTEM,
                     name: "kernel", purl: "pkg:generic/linux/kernel",
                     cpe: "cpe:2.3:o:linux:linux_kernel:*:..." } ]
vulnerabilities: [ { id: CVE-*, source: {name: NVD},
                     description, ratings (CVSSv3), cwes,
                     published, updated,
                     affects: [ { ref: "linux-kernel",
                                  versions: [ {range: "vers:generic/>=5.15|<5.15.103", status: AFFECTED},
                                              {version: "5.15.103", status: UNAFFECTED}, … ] } ],
                     properties: [ {name: "dependency-track:vuln:reference-url",
                                    value: "https://kernelscan.io/cve/CVE-*"} ] } ]
```

**Open question #2:** exact `vers` range scheme the internal analyzer matches
against `pkg:generic/linux/kernel` purls — align with what the OSV data source
emits (`ModelConverter` upstream) during slice 2.

## Building

The DT plugin API (`plugin-api`, `vuln-data-source-api`, `cyclonedx-proto`) is
**not published to Maven Central**; the build extracts the jars from the pinned
official apiserver image — which also makes the version coupling explicit
(a plugin binary targets one DT release; rebuild per minor).

```bash
make libs    # extract compile classpath from ghcr.io/dependencytrack/apiserver:5.0.2
make build   # javac + jar inside eclipse-temurin:25-jdk (Java 25 = DT's baseline)
make deploy  # scp to the m2 test instance + restart apiserver (dev only)
```

## Verification plan (slice 2)

1. Mount into the m2 v5 testbed, enable + configure via admin UI (sample1 feed
   token), trigger mirror, watch `MirrorVulnDataSourceActivity` logs.
2. Fastlane: pick a CVE present in KernelScan but not NVD → appears in DT under
   NVD identity; findings show on the Helios kernel components after analysis.
3. Enrichment/ownership: pick a CVE both have → observe whether our ranges land
   (open question #1); re-run NVD mirror → observe convergence.
4. Watermark: second mirror run processes ~0 records.
5. Log at WARN for anything operational — DT's logback root is WARN and drops
   third-party INFO.

## License note

Interfaces compiled against Dependency-Track (Apache-2.0). This repo is
private/proprietary KernelScan code; an eventual upstream contribution of a
KernelScan module would be a separate, Apache-2.0-licensed effort.
