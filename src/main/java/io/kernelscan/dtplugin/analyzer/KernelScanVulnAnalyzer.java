/*
 * Copyright (c) 2026 KernelScan UG (haftungsbeschränkt)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package io.kernelscan.dtplugin.analyzer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.cyclonedx.proto.v1_7.VulnerabilityAffects;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Config-aware Linux-kernel vulnerability analyzer.
 * <p>
 * For each kernel component in the project BOM, resolves the customer's
 * KernelScan <em>product</em> for that kernel version + architecture, fetches
 * its config-aware VEX, and reports the CVEs that are actually reachable in
 * that kernel's {@code .config} (VEX state != {@code not_affected}), under
 * plain {@code CVE-*} / {@code NVD} identity.
 * <p>
 * This is what distinguishes KernelScan from DT's stock NVD analyzer: NVD
 * matches every CVE for the kernel version (config-blind); KernelScan reports
 * only the config-reachable set, and can introduce kernel CVEs NVD does not
 * yet carry. The complementary {@code not_affected} verdicts for CVEs NVD
 * surfaces are delivered as a CycloneDX VEX ({@code PUT /api/v1/vex}) — DT
 * applies analysis only from VEX imports / CEL policies, never from an
 * analyzer's VDR, so an analyzer cannot itself suppress a finding.
 * <p>
 * Failures are contained: a KernelScan outage, bad API key, or missing product
 * degrades to "no findings from this analyzer" (logged), never a failed
 * project analysis. {@link InterruptedException} is propagated so DT can cancel.
 */
final class KernelScanVulnAnalyzer implements VulnAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(KernelScanVulnAnalyzer.class);

    private static final String KERNEL_PURL_PREFIX = "pkg:generic/linux/kernel@";
    private static final String KERNEL_CPE_MARKER = ":o:linux:linux_kernel:";
    static final String VERSION = versionOf();
    private static final String USER_AGENT = "kernelscan-dt-plugin/" + VERSION;

    /** Resolved product VEX cache, shared across analyses (a new analyzer is created per run). */
    private static final Object CACHE_LOCK = new Object();
    private static final Map<String, CachedVex> CACHE = new LinkedHashMap<>();

    private record CachedVex(Instant fetchedAt, JsonNode vex) {
    }

    /** Non-2xx / non-retryable API response — caught by {@link #analyze} for graceful degradation. */
    private static final class ApiException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        ApiException(final String message) {
            super(message);
        }

        ApiException(final String message, final Throwable cause) {
            super(message, cause);
        }
    }

    private final KernelScanVulnAnalyzerConfigV1 config;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final VexModelConverter converter = new VexModelConverter();

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
        // Kernel components in the BOM, by bom-ref -> version.
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
            try {
                collectFindings(kernelVersion, bomRef, vulnsById);
            } catch (ApiException e) {
                // Contain the failure: this analyzer contributes nothing for this
                // kernel, but the project analysis (and other analyzers) proceed.
                LOGGER.warn("KernelScan analyzer: skipping kernel {} ({})", kernelVersion, e.getMessage());
            }
        }

        final Bom.Builder vdr = Bom.newBuilder().setSpecVersion("1.7");
        vulnsById.values().forEach(vdr::addVulnerabilities);
        return vdr.build();
    }

    private void collectFindings(
            final String kernelVersion,
            final String bomRef,
            final Map<String, Vulnerability.Builder> vulnsById) throws InterruptedException {
        final JsonNode vex = resolveProductVex(kernelVersion);
        if (vex == null) {
            LOGGER.warn("KernelScan analyzer: no product for kernel {} arch {}; skipping",
                    kernelVersion, config.getArch());
            return;
        }

        int reachable = 0, gated = 0;
        for (final JsonNode vuln : vex.path("vulnerabilities")) {
            final String cveId = vuln.path("id").asText(null);
            if (cveId == null || !cveId.startsWith("CVE-")) {
                continue;
            }
            final String state = vuln.path("analysis").path("state").asText("exploitable");
            if ("not_affected".equals(state)) {
                gated++; // config-gated: not a finding; the not_affected verdict rides the VEX channel
                continue;
            }
            reachable++;
            vulnsById.computeIfAbsent(cveId, id -> converter.toVulnerabilityBuilder(vuln, id))
                    .addAffects(VulnerabilityAffects.newBuilder().setRef(bomRef));
        }
        LOGGER.info("KernelScan analyzer: kernel {} -> {} config-reachable CVE(s), {} config-gated",
                kernelVersion, reachable, gated);
    }

    static String kernelVersionOf(final Component component) {
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
        for (final JsonNode p : getJson("/api/products")) {
            if (kernelVersion.equals(p.path("kernel_version").asText())
                    && config.getArch().equals(p.path("arch").asText())) {
                return p.path("id").asText(null);
            }
        }
        return null;
    }

    private JsonNode getJson(final String path) throws InterruptedException {
        final URI uri = URI.create(config.getApiBaseUrl().replaceAll("/+$", "") + path);
        final HttpResponse<byte[]> response;
        try {
            final HttpRequest request = HttpRequest.newBuilder(uri)
                    .header("Authorization", "Bearer " + config.getApiKey())
                    .header("Accept", "application/json")
                    .header("User-Agent", USER_AGENT)
                    .GET()
                    .build();
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new ApiException(uri.getHost() + " unreachable: " + e.getMessage(), e);
        }
        final int status = response.statusCode();
        if (status == 401 || status == 403) {
            throw new ApiException("API key rejected (HTTP " + status + ") — check the configured KernelScan API key");
        }
        if (status != 200) {
            throw new ApiException(path + " returned HTTP " + status);
        }
        try {
            return objectMapper.readTree(response.body());
        } catch (IOException e) {
            throw new ApiException("invalid JSON from " + path + ": " + e.getMessage(), e);
        }
    }

    private static String versionOf() {
        final String v = KernelScanVulnAnalyzer.class.getPackage().getImplementationVersion();
        return v != null ? v : "dev";
    }

}