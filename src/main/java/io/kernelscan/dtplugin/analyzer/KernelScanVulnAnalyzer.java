package io.kernelscan.dtplugin.analyzer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.kernelscan.dtplugin.source.FeedModelConverter;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.cyclonedx.proto.v1_7.VulnerabilityAffects;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Config-aware kernel analyzer (the customer setup).
 * <p>
 * For each Linux-kernel component in the project BOM, resolves the customer's
 * KernelScan <em>product</em> for that kernel version + architecture, fetches
 * its config-aware VEX, and reports the CVEs that are actually reachable in
 * that kernel's {@code .config} (VEX state != {@code not_affected}).
 * <p>
 * This is what distinguishes KernelScan from DT's stock NVD analyzer: NVD
 * matches every CVE for the kernel version (config-blind); KernelScan reports
 * only the config-reachable set. The complementary {@code not_affected}
 * verdicts for the CVEs NVD surfaces are delivered separately as a CycloneDX
 * VEX ({@code PUT /api/v1/vex}) — DT applies analysis from VEX imports and CEL
 * policies, never from an analyzer's VDR, so an analyzer cannot itself suppress
 * a finding. The VDR here still carries per-vuln {@code analysis} for
 * forward-compatibility, but DT 5.0.2 ignores it.
 */
final class KernelScanVulnAnalyzer implements VulnAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(KernelScanVulnAnalyzer.class);
    private static final String KERNEL_PURL_PREFIX = "pkg:generic/linux/kernel@";
    private static final String KERNEL_CPE_MARKER = ":o:linux:linux_kernel:";

    /** Resolved product VEX cache, shared across analyses (create() is per-run). */
    private static final Object CACHE_LOCK = new Object();
    private static final Map<String, CachedVex> CACHE = new LinkedHashMap<>();

    private record CachedVex(Instant fetchedAt, JsonNode vex) {
    }

    private final KernelScanVulnAnalyzerConfigV1 config;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final FeedModelConverter converter = new FeedModelConverter();

    KernelScanVulnAnalyzer(
            final KernelScanVulnAnalyzerConfigV1 config,
            final HttpClient httpClient,
            final ObjectMapper objectMapper) {
        this.config = config;
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
    }

    @Override
    public Bom analyze(final Bom bom) throws InterruptedException {
        final Map<String, String> kernelVersionByRef = new LinkedHashMap<>();
        for (final Component component : bom.getComponentsList()) {
            final String version = kernelVersionOf(component);
            if (version != null && component.hasBomRef()) {
                kernelVersionByRef.put(component.getBomRef(), version);
            }
        }
        if (kernelVersionByRef.isEmpty()) {
            return Bom.newBuilder().build();
        }

        final Map<String, Vulnerability.Builder> vulnsById = new LinkedHashMap<>();
        for (final Map.Entry<String, String> entry : kernelVersionByRef.entrySet()) {
            final String bomRef = entry.getKey();
            final String kernelVersion = entry.getValue();

            final JsonNode vex = resolveProductVex(kernelVersion);
            if (vex == null) {
                LOGGER.warn("KernelScan analyzer: no product found for kernel {} arch {}",
                        kernelVersion, config.getArch());
                continue;
            }

            int reachable = 0, suppressed = 0;
            for (final JsonNode vuln : vex.path("vulnerabilities")) {
                final String cveId = vuln.path("id").asText(null);
                if (cveId == null || !cveId.startsWith("CVE-")) {
                    continue;
                }
                final String state = vuln.path("analysis").path("state").asText("exploitable");
                if ("not_affected".equals(state)) {
                    suppressed++;           // config-gated: not a finding, handled by the VEX channel
                    continue;
                }
                reachable++;
                final Vulnerability.Builder builder = vulnsById.computeIfAbsent(
                        cveId, id -> converter.toVulnerabilityBuilder(vuln, id));
                builder.addAffects(VulnerabilityAffects.newBuilder().setRef(bomRef));
            }
            LOGGER.warn("KernelScan analyzer: kernel {} -> {} config-reachable CVE(s), {} config-gated (VEX-suppressed)",
                    kernelVersion, reachable, suppressed);
        }

        final Bom.Builder vdr = Bom.newBuilder().setSpecVersion("1.7");
        vulnsById.values().forEach(vdr::addVulnerabilities);
        return vdr.build();
    }

    private static String kernelVersionOf(final Component component) {
        if (component.hasPurl() && component.getPurl().startsWith(KERNEL_PURL_PREFIX)) {
            final String rest = component.getPurl().substring(KERNEL_PURL_PREFIX.length());
            final int q = rest.indexOf('?');
            return q >= 0 ? rest.substring(0, q) : rest;
        }
        if (component.hasCpe() && component.getCpe().contains(KERNEL_CPE_MARKER)) {
            final String[] parts = component.getCpe().split(":");
            if (parts.length > 5 && !parts[5].isEmpty() && !"*".equals(parts[5])) {
                return parts[5];
            }
        }
        return null;
    }

    // ── product resolution + config-aware VEX fetch ──────────────────────────

    private JsonNode resolveProductVex(final String kernelVersion) throws InterruptedException {
        final String cacheKey = kernelVersion + "|" + config.getArch();
        final Duration ttl = Duration.ofMinutes(config.getCacheMinutes());
        synchronized (CACHE_LOCK) {
            final CachedVex cached = CACHE.get(cacheKey);
            if (cached != null && cached.fetchedAt().isAfter(Instant.now().minus(ttl))) {
                return cached.vex();
            }
        }

        final String productId = findProductId(kernelVersion);
        if (productId == null) {
            return null;
        }
        final JsonNode vex = getJson("/api/products/" + productId + "/vex");
        synchronized (CACHE_LOCK) {
            CACHE.put(cacheKey, new CachedVex(Instant.now(), vex));
        }
        return vex;
    }

    /** First product whose kernel_version + arch match; null if none. */
    private String findProductId(final String kernelVersion) throws InterruptedException {
        final JsonNode products = getJson("/api/products");
        for (final JsonNode p : products) {
            if (kernelVersion.equals(p.path("kernel_version").asText())
                    && config.getArch().equals(p.path("arch").asText())) {
                return p.path("id").asText(null);
            }
        }
        return null;
    }

    private JsonNode getJson(final String path) throws InterruptedException {
        final URI uri = URI.create(config.getApiBaseUrl().replaceAll("/+$", "") + path);
        try {
            final HttpRequest request = HttpRequest.newBuilder(uri)
                    .header("Authorization", "Bearer " + config.getApiKey())
                    .header("Accept", "application/json")
                    .header("User-Agent", "kernelscan-dt-plugin")
                    .GET()
                    .build();
            final HttpResponse<byte[]> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != 200) {
                throw new IllegalStateException(
                        "KernelScan API " + path + " returned HTTP " + response.statusCode());
            }
            return objectMapper.readTree(response.body());
        } catch (IOException e) {
            throw new UncheckedIOException("KernelScan API request failed: " + path, e);
        }
    }


}
