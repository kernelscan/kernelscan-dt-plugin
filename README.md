# kernelscan-dt-plugin

Dependency-Track **v5** plugin shipping KernelScan extensions — a **fast lane
for Linux kernel CVEs** (KernelScan publishes ahead of NVD ~90% of the time)
and **better kernel version matching** than NVD's CPE ranges (per-branch
introduced/fixed intervals from kernel.org / cvelistV5 enrichment).

Two extensions in one JAR (evaluated live 2026-07-05, DT 5.0.2 on the m2
testbed — see "Evaluation results"):

| Extension | Slot | Status |
|---|---|---|
| `vuln-analyzer/kernelscan` | Snyk/VulnDB-style per-project analyzer | **WORKING** — the production path |
| `vuln-data-source/kernelscan` | DB-wide mirror (nvd/osv/github slot) | **BLOCKED in 5.0.2** — needs upstream fix |

## Customer-like parallel setup (validated 2026-07-06, m2 testbed)

The target live deployment: a customer SBOM identifying the kernel by **CPE**,
DT's stock NVD analyzer running, and KernelScan layered on top for config-aware
triage. Two KernelScan channels, because **DT v5 analyzers produce findings
only** — analysis/verdicts are applied exclusively by the CEL policy engine or
VEX import (`CycloneDXVexImporter`), never from an analyzer's VDR:

1. **Analyzer (config-aware findings).** `vuln-analyzer/kernelscan` in *product
   mode*: reads the kernel version from the component CPE, resolves the
   customer's KernelScan product (by version + arch via the account API key),
   fetches its config-aware VEX, and reports only the **config-reachable** CVEs
   (VEX state != `not_affected`) under `(CVE-*, NVD)` identity.
2. **VEX (config verdicts).** A companion push (`dtrack-test/push_vex.py`,
   standing in for the customer's in-network connector/CI) `PUT /api/v1/vex`
   with the same product VEX. DT applies the per-CVE `not_affected` +
   justification onto the findings NVD surfaced — the config-symbol triage.

Result on the three Helios projects (CPE-only kernel SBOM, NVD analyzer +
KernelScan analyzer + config VEX):

| kernel | findings (NVD, config-blind) | active after config triage | auto-suppressed `not_affected` |
|---|---|---|---|
| 5.15.102 | 5,230 | 1,627 | 3,603 |
| 6.1.86 | 4,487 | 1,313 | 3,174 |
| 6.6.69 | 3,280 | 985 | 2,295 |

- Single `(CVE-*, NVD)` identity throughout (`VULNERABILITY` all source NVD, no
  duplicates); 9,072 `NOT_AFFECTED` + 2,601 `EXPLOITABLE` analyses applied across
  the three, each carrying KernelScan's justification (`CODE_NOT_PRESENT`, …) and
  config-mapping detail text.
- The analyzer alone reported the config-reachable set (5.15.102: 1,046 reachable
  / 4,432 gated) — genuinely config-aware, not version-only.
- VEX binds via the metadata-component path: `affects.ref` → `metadata.component`
  makes DT apply to *all* project components vulnerable to that CVE
  (`getAllVulnerableComponents`), so no component-identity match is needed and the
  CPE-only SBOM works.

Notes for the real deployment: the analyzer needs the customer's `ks_live_…` API
key (config field `apiKey`); the VEX channel needs a DT API key + the same
KernelScan key and runs inside the customer network (analyzers get only the BOM,
not the DT project UUID / DT auth, so they cannot push the VEX themselves).

## Patched-apiserver experiment (2026-07-05) — data source unblocked, and what it revealed

To see what the data-source path actually does once the enum guard is removed,
we ran a **one-line apiserver patch** on the test instance
(`kernelscan-ops/dtrack-test/apiserver-patch/`): `VulnDataSourceMirrorService`
maps extension `kernelscan` → source `NVD` instead of the failing
`uppercase(extensionName)`. Deployed by prepending a patch JAR to the
apiserver classpath (`-cp 'patch/*:apiserver.jar:lib/*'`), no image rebuild.

The mirror then **ran end-to-end** (12,247 BOVs, ~33 s):

- **Phase 1 (NVD source enabled):** every record `skip`ped — the update policy
  (`isUpdatableByDataSource`, `vulnSource=NVD` owned by the enabled NVD mirror)
  correctly refused to touch NVD-owned rows. Nothing mutated. Confirms the
  fastlane/ownership design is real and safe.
- **Phase 2 (NVD source disabled):** all 12,247 NVD records **enriched in
  place** with our per-branch affected ranges — 3,746 `pkg:generic/linux/kernel`
  `VulnerableSoftware` rows linked onto the existing NVD vulnerabilities under
  **single NVD identity, zero duplicates**. This is the enrichment goal working
  through the data-source slot.

**But re-analysis exposed two real matching bugs in *our* BOV mapping** — DT's
`BovModelConverter` has semantics we have to respect:

1. **Component CPE → catastrophic over-match.** We put a wildcard-version CPE
   (`linux_kernel:*`) on the emitted component. DT turns that into a single
   *unbounded, globally-deduplicated* `VulnerableSoftware` row shared across
   every vulnerability, so every kernel component matched **12,219 / 12,247**
   CVEs. Fix: **emit purl only, no CPE** — purl-range rows match precisely.
2. **`unaffected` version pins stored as vulnerable.** `BovModelConverter`
   records *every* `affects.versions[]` entry as `vulnerable=true`, ignoring
   `status`. Our exact `unaffected: <fix>` pins (e.g. `6.6.121`) therefore
   claimed the fixed release IS vulnerable. Fix: **emit only `affected`
   entries** (the ranges already encode `< fix`); drop the `unaffected` pins.

Both fixed in `FeedModelConverter`; re-validated below. Lesson: the analyzer
path never touched `BovModelConverter` (it returns findings directly), so these
were invisible until the data-source path ran — a good argument for keeping the
analyzer as the primary integration and the data source as opt-in enrichment.

## Evaluation results (2026-07-05, m2 testbed)

**Data source:** mirror run fails terminally with `Invalid source name:
KERNELSCAN` — `VulnDataSourceMirrorService` derives the vulnerability source
as `uppercase(extensionName)` and requires a known `Vulnerability.Source` enum
value. Third-party source identities aren't wired through yet (ADR-010's
"community data sources (soon)"). Ironically the underlying
`VulnerabilityUpdatePolicy.isUpdatableByDataSource` already implements exactly
our fastlane semantics ("allow a non-authoritative data source to fill the gap
until the authoritative one catches up"). **Upstream ask:** let a
`VulnDataSourceFactory` declare its vulnerability source (or honor per-BOV
sources). Code stays in the JAR, inert until then.

**Analyzer:** full success on the Helios Virt showcase projects —
- `ReconcileVulnAnalysisResultsActivity` honors the **per-vuln source from the
  VDR** (and even derives NVD from a `CVE-*` id), so our `(CVE-*, NVD)`
  identity **merged with the existing NVD records: zero duplicates, zero new
  identities** (`VULNERABILITY` count unchanged).
- 5.15.102: 12,247-record corpus fetched once (~26 s, then in-memory cache),
  5,665 affecting CVEs reported in ~150 ms; findings 5,033 → **6,206** —
  **+1,173 CVEs the NVD-CPE internal analyzer missed**, 4,492 dual-attributed
  (`FINDINGATTRIBUTION`: kernelscan + internal).
- Version matching happens plugin-side against the feed's per-branch intervals
  — no DT-side `vers`-range interpretation involved (former open question #2
  is moot for this path).
- Fastlane record creation (CVE not yet in DT → created under NVD identity by
  first report) is code-verified; not yet observed live because all 12,247
  windowed feed CVEs already existed in DT's NVD mirror — it will fire when an
  early-disclosed CVE (oss-security watcher) hits the feed before NVD.
- Metadata enrichment of *existing* NVD records is blocked by design while the
  NVD data source is enabled (`isUpdatableByAnalyzer`) — our richer data lands
  only on fastlane-created records. Acceptable; revisit with upstream.
- Idempotent re-analysis, corpus cache shared across projects (one fetch,
  three analyses), findings stable on re-run.

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
