package io.kernelscan.dtplugin.source;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cyclonedx.proto.v1_7.Bom;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.NoSuchElementException;

/**
 * Mirrors KernelScan's kernel-CVE feed into Dependency-Track as CycloneDX BOVs.
 * <p>
 * One BOV per CVE, carrying plain {@code CVE-*} ids under {@code source=NVD}
 * (see README — fastlane + enrichment identity strategy). Incremental
 * mirroring is client-side for now: records are filtered by their
 * {@code updated} timestamp against a watermark persisted in the plugin
 * {@link KeyValueStore}; the watermark commits once the run drains
 * (feed order is not guaranteed, so mid-run commits could skip records).
 * <p>
 * NOTE: operational logging is at WARN on purpose where visibility matters —
 * DT's logback root is WARN and drops third-party INFO.
 */
final class KernelScanVulnDataSource implements VulnDataSource {

    private static final Logger LOGGER = LoggerFactory.getLogger(KernelScanVulnDataSource.class);
    private static final String WATERMARK_KEY = "watermark.v1";

    private final KernelScanVulnDataSourceConfigV1 config;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final KeyValueStore kvStore;
    private final FeedModelConverter converter = new FeedModelConverter();

    private Deque<Bom> pending;          // null until first fetch
    private Instant watermark;           // committed watermark from KV store
    private Instant maxUpdatedProcessed; // in-memory high-water of markProcessed() acks

    KernelScanVulnDataSource(
            final KernelScanVulnDataSourceConfigV1 config,
            final HttpClient httpClient,
            final ObjectMapper objectMapper,
            final KeyValueStore kvStore) {
        this.config = config;
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.kvStore = kvStore;
    }

    @Override
    public boolean hasNext() {
        ensureFetched();
        if (pending.isEmpty()) {
            maybeCommitWatermark();
            return false;
        }
        return true;
    }

    @Override
    public Bom next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        return pending.poll();
    }

    @Override
    public void markProcessed(final Bom bov) {
        // DT durably stored this BOV — advance the in-memory high-water mark.
        // Committed to the KV store only once the run drains (see hasNext).
        final Instant updated = converter.updatedOf(bov);
        if (updated != null
                && (maxUpdatedProcessed == null || updated.isAfter(maxUpdatedProcessed))) {
            maxUpdatedProcessed = updated;
        }
    }

    // ── internal ─────────────────────────────────────────────────────────────

    private void ensureFetched() {
        if (pending != null) {
            return;
        }
        pending = new ArrayDeque<>();
        watermark = readWatermark();

        final URI uri = URI.create("%s/t/%s/cyclonedx/all.json"
                .formatted(config.getFeedBaseUrl().replaceAll("/+$", ""), config.getFeedToken()));
        LOGGER.debug("Fetching KernelScan feed from {}", uri.getHost());

        final JsonNode root;
        try {
            final HttpRequest request = HttpRequest.newBuilder(uri)
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
            root = objectMapper.readTree(response.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while fetching KernelScan feed", e);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to fetch KernelScan feed", e);
        }

        int total = 0, skipped = 0;
        for (final JsonNode vulnNode : root.path("vulnerabilities")) {
            total++;
            final Instant updated = converter.updatedOf(vulnNode);
            if (config.isIncrementalMirroringEnabled()
                    && watermark != null && updated != null && !updated.isAfter(watermark)) {
                skipped++;
                continue; // below watermark — already mirrored
            }
            final Bom bov = converter.toBov(vulnNode);
            if (bov != null) {
                pending.add(bov);
            }
        }
        // WARN so it shows up under DT's default logback (root=WARN).
        LOGGER.warn("KernelScan feed: {} record(s) total, {} below watermark, {} to mirror",
                total, skipped, pending.size());
    }

    private Instant readWatermark() {
        if (!config.isIncrementalMirroringEnabled()) {
            return null;
        }
        final KeyValueStore.Entry entry = kvStore.get(WATERMARK_KEY);
        return entry != null ? Instant.parse(entry.value()) : null;
    }

    private void maybeCommitWatermark() {
        if (!config.isIncrementalMirroringEnabled() || maxUpdatedProcessed == null) {
            return;
        }
        if (watermark == null || maxUpdatedProcessed.isAfter(watermark)) {
            kvStore.put(WATERMARK_KEY, maxUpdatedProcessed.toString());
            LOGGER.warn("KernelScan watermark advanced to {}", maxUpdatedProcessed);
            watermark = maxUpdatedProcessed;
        }
        maxUpdatedProcessed = null; // idempotent on repeated hasNext() == false
    }

}
