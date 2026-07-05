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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reports kernel CVEs affecting the exact kernel version of matched
 * components. Version matching happens here (KernelScan's competence), not
 * via DT-side range interpretation — the VDR carries only concrete
 * {@code affects.ref} entries pointing at the input components.
 */
final class KernelScanVulnAnalyzer implements VulnAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(KernelScanVulnAnalyzer.class);
    private static final String KERNEL_PURL_PREFIX = "pkg:generic/linux/kernel@";
    private static final String KERNEL_CPE_MARKER = ":o:linux:linux_kernel:";

    /** Corpus cache shared across analyses (create() returns a new instance per run). */
    private static final Object CACHE_LOCK = new Object();
    private static volatile CachedFeed cachedFeed;

    private record CachedFeed(String url, Instant fetchedAt, JsonNode root) {
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
        // Kernel components in the project BOM, keyed by bom-ref.
        final Map<String, String> kernelVersionByRef = new HashMap<>();
        for (final Component component : bom.getComponentsList()) {
            final String version = kernelVersionOf(component);
            if (version != null && component.hasBomRef()) {
                kernelVersionByRef.put(component.getBomRef(), version);
            }
        }
        if (kernelVersionByRef.isEmpty()) {
            return Bom.newBuilder().build();
        }

        final JsonNode feed = fetchFeed();

        // One vulnerability entry per affecting CVE, affects[] carrying every
        // matched kernel component's bom-ref.
        final Map<String, Vulnerability.Builder> vulnsById = new LinkedHashMap<>();
        int matched = 0;
        for (final JsonNode record : feed.path("vulnerabilities")) {
            final String cveId = record.path("id").asText(null);
            if (cveId == null || !cveId.startsWith("CVE-")) {
                continue;
            }
            final List<String> affectedRefs = new ArrayList<>(1);
            for (final Map.Entry<String, String> entry : kernelVersionByRef.entrySet()) {
                if (converter.affectsKernelVersion(record, entry.getValue())) {
                    affectedRefs.add(entry.getKey());
                }
            }
            if (affectedRefs.isEmpty()) {
                continue;
            }
            matched++;
            final Vulnerability.Builder vuln = vulnsById.computeIfAbsent(
                    cveId, id -> converter.toVulnerabilityBuilder(record, id));
            for (final String ref : affectedRefs) {
                vuln.addAffects(VulnerabilityAffects.newBuilder().setRef(ref));
            }
        }

        LOGGER.warn("KernelScan analyzer: {} kernel component(s), {} affecting CVE(s)",
                kernelVersionByRef.size(), matched);

        final Bom.Builder vdr = Bom.newBuilder().setSpecVersion("1.7");
        vulnsById.values().forEach(vdr::addVulnerabilities);
        return vdr.build();
    }

    private static String kernelVersionOf(final Component component) {
        if (component.hasPurl() && component.getPurl().startsWith(KERNEL_PURL_PREFIX)) {
            final String rest = component.getPurl().substring(KERNEL_PURL_PREFIX.length());
            final int qualifiers = rest.indexOf('?');
            return qualifiers >= 0 ? rest.substring(0, qualifiers) : rest;
        }
        if (component.hasCpe() && component.getCpe().contains(KERNEL_CPE_MARKER)) {
            final String[] parts = component.getCpe().split(":");
            if (parts.length > 5 && !parts[5].isEmpty() && !"*".equals(parts[5])) {
                return parts[5];
            }
        }
        return null;
    }

    private JsonNode fetchFeed() throws InterruptedException {
        final String url = "%s/t/%s/cyclonedx/all.json"
                .formatted(config.getFeedBaseUrl().replaceAll("/+$", ""), config.getFeedToken());

        final CachedFeed cached = cachedFeed;
        final Duration ttl = Duration.ofMinutes(config.getFeedCacheMinutes());
        if (cached != null && cached.url().equals(url)
                && cached.fetchedAt().isAfter(Instant.now().minus(ttl))) {
            return cached.root();
        }

        synchronized (CACHE_LOCK) {
            final CachedFeed recheck = cachedFeed;
            if (recheck != null && recheck.url().equals(url)
                    && recheck.fetchedAt().isAfter(Instant.now().minus(ttl))) {
                return recheck.root();
            }
            try {
                final HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                        .header("Accept", "application/json")
                        .header("User-Agent", "kernelscan-dt-plugin")
                        .GET()
                        .build();
                final HttpResponse<byte[]> response =
                        httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
                if (response.statusCode() != 200) {
                    throw new IllegalStateException(
                            "KernelScan feed returned HTTP " + response.statusCode());
                }
                final JsonNode root = objectMapper.readTree(response.body());
                cachedFeed = new CachedFeed(url, Instant.now(), root);
                LOGGER.warn("KernelScan analyzer: fetched feed corpus ({} records)",
                        root.path("vulnerabilities").size());
                return root;
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to fetch KernelScan feed", e);
            }
        }
    }

}
