# Security & Privacy

This plugin runs **in-process inside your Dependency-Track apiserver**, so its
data flow deserves a precise statement. It is small on purpose — read the source
(`src/main/java/io/kernelscan/dtplugin/analyzer/`) and verify all of the below.

## What it sends

During a project analysis, for each Linux-kernel component in the BOM the plugin
makes two **outbound HTTPS GET** requests to the configured KernelScan API
(`apiBaseUrl`, default `https://kernelscan.io`), authenticated with your
`ks_live_…` API key:

- `GET /api/products` — to resolve which of *your own* KernelScan products
  matches the kernel version + architecture.
- `GET /api/products/{id}/vex` — to fetch that product's config-aware VEX.

That is the complete outbound surface. See `KernelScanVulnAnalyzer.getJson(...)`.

## What it does NOT send

- It does **not** transmit your SBOM, component inventory, dependency graph,
  findings, or any project data to KernelScan or anywhere else.
- It makes no other network calls, opens no listeners, writes no files, and
  spawns no processes.
- The only environment-derived value that influences a request is the kernel
  **version string** (used to select a product you already registered) — nothing
  is uploaded to derive it.

The plugin is effectively a **read-only client**: it fetches verdicts you have
already computed in your KernelScan account and maps them to DT findings.

## Credentials & permissions

- The KernelScan API key is stored by DT as a managed secret (plugin config).
- Recommended DT API-key scope for the companion VEX push (separate component,
  not this plugin): `VULNERABILITY_ANALYSIS`, `VIEW_PORTFOLIO`.

## Failure containment

A KernelScan outage, rejected key (HTTP 401/403), or missing product degrades to
"no findings from this analyzer" — it never fails the project analysis or affects
other analyzers. `InterruptedException` is propagated so DT can cancel.

## Reporting a vulnerability

Please report security issues privately to **support@kernelscan.io** rather than
opening a public issue. We aim to acknowledge within 3 business days.
