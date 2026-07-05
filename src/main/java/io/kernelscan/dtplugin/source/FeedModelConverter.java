package io.kernelscan.dtplugin.source;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.protobuf.Timestamp;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Classification;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.ScoreMethod;
import org.cyclonedx.proto.v1_7.Severity;
import org.cyclonedx.proto.v1_7.Source;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.cyclonedx.proto.v1_7.VulnerabilityAffectedStatus;
import org.cyclonedx.proto.v1_7.VulnerabilityAffectedVersions;
import org.cyclonedx.proto.v1_7.VulnerabilityAffects;
import org.cyclonedx.proto.v1_7.VulnerabilityRating;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Locale;

/**
 * Converts one KernelScan CycloneDX-JSON feed vulnerability record
 * ({@code /feed/t/{token}/cyclonedx/all.json}, see backend
 * {@code app/feed_formats.py:to_cdx_vulnerability}) into a CycloneDX
 * protobuf (v1_7) BOV for DT's vuln-data-source mirror.
 * <p>
 * Identity: plain {@code CVE-*} id, {@code source=NVD} — fastlane records
 * land under their final identity, enrichment targets the NVD namespace
 * (README, "Identity" section).
 */
public final class FeedModelConverter {

    private static final Logger LOGGER = LoggerFactory.getLogger(FeedModelConverter.class);

    static final String KERNEL_BOM_REF = "linux-kernel";
    private static final String KERNEL_PURL = "pkg:generic/linux/kernel";
    private static final String KERNEL_CPE = "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*";

    /**
     * The one component every emitted vulnerability affects.
     * <p>
     * PURL ONLY — deliberately no CPE. DT's BovModelConverter synthesizes
     * CPE-keyed VulnerableSoftware rows from a component CPE, and a wildcard
     * version CPE ({@code linux_kernel:*}) combined with exact-version affects
     * entries collapses into ONE unbounded, globally-deduplicated VS row shared
     * by every vulnerability — making every kernel component match every CVE
     * (observed live 2026-07-05: 12,219/12,247 false matches on 5.15.102).
     * Purl-range rows carry the same matching information safely.
     */
    private static final Component KERNEL_COMPONENT = Component.newBuilder()
            .setBomRef(KERNEL_BOM_REF)
            .setType(Classification.CLASSIFICATION_OPERATING_SYSTEM)
            .setName("kernel")
            .setPurl(KERNEL_PURL)
            .build();

    /**
     * One BOV per CVE. Returns {@code null} for records that cannot be
     * converted (logged; the mirror run continues).
     */
    public Bom toBov(final JsonNode vuln) {
        final String cveId = vuln.path("id").asText(null);
        if (cveId == null || !cveId.startsWith("CVE-")) {
            LOGGER.warn("Skipping feed record without CVE id: {}", vuln.path("id").asText("?"));
            return null;
        }
        try {
            final Vulnerability.Builder vulnBuilder = toVulnerabilityBuilder(vuln, cveId);

            // Per-branch affected intervals -> one affects entry on the kernel
            // component carrying every branch's ranges. Range syntax is
            // translated to CycloneDX `vers` (open question #2 in the README:
            // align with what the internal analyzer matches).
            final var affectsBuilder = VulnerabilityAffects.newBuilder().setRef(KERNEL_BOM_REF);
            for (final JsonNode affect : vuln.path("affects")) {
                for (final JsonNode version : affect.path("versions")) {
                    final VulnerabilityAffectedVersions converted = convertVersion(version);
                    if (converted != null) {
                        affectsBuilder.addVersions(converted);
                    }
                }
            }
            if (affectsBuilder.getVersionsCount() > 0) {
                vulnBuilder.addAffects(affectsBuilder);
            }

            return Bom.newBuilder()
                    .setSpecVersion("1.7")
                    .addComponents(KERNEL_COMPONENT)
                    .addVulnerabilities(vulnBuilder)
                    .build();
        } catch (RuntimeException e) {
            LOGGER.warn("Failed to convert feed record {}", cveId, e);
            return null;
        }
    }

    /**
     * Metadata-only proto vulnerability (no affects) — shared by the data
     * source's BOV assembly and the analyzer's VDR assembly. Identity: plain
     * CVE id, source NVD.
     */
    public Vulnerability.Builder toVulnerabilityBuilder(final JsonNode vuln, final String cveId) {
        final var vulnBuilder = Vulnerability.newBuilder()
                    .setId(cveId)
                    .setSource(Source.newBuilder()
                            .setName("NVD")
                            .setUrl("https://nvd.nist.gov/vuln/detail/" + cveId));

            if (vuln.hasNonNull("description")) {
                vulnBuilder.setDescription(vuln.get("description").asText());
            }
            if (vuln.hasNonNull("detail")) {
                vulnBuilder.setDetail(vuln.get("detail").asText()); // curated short name
            }
            for (final JsonNode cwe : vuln.path("cwes")) {
                vulnBuilder.addCwes(cwe.asInt());
            }
            for (final JsonNode rating : vuln.path("ratings")) {
                final VulnerabilityRating converted = convertRating(rating);
                if (converted != null) {
                    vulnBuilder.addRatings(converted);
                }
            }
            final Instant published = parseInstant(vuln.path("published").asText(null));
            if (published != null) {
                vulnBuilder.setPublished(toTimestamp(published));
            }
        final Instant updated = parseInstant(vuln.path("updated").asText(null));
        if (updated != null) {
            vulnBuilder.setUpdated(toTimestamp(updated));
        }

        // DT convention: link back to the analyzer/source-specific page.
        vulnBuilder.addProperties(Property.newBuilder()
                .setName("dependency-track:vuln:reference-url")
                .setValue("https://kernelscan.io/cve/" + cveId));

        return vulnBuilder;
    }

    /**
     * Does this feed record affect the given kernel version? Evaluates the
     * per-branch {@code affects[].versions[]} intervals ({@code ">=X <Y"},
     * {@code ">=X"}, {@code "<Y"}) against a dotted kernel version. Exact
     * {@code unaffected} fix versions win over range hits.
     */
    public boolean affectsKernelVersion(final JsonNode vuln, final String kernelVersion) {
        boolean affected = false;
        for (final JsonNode affect : vuln.path("affects")) {
            for (final JsonNode version : affect.path("versions")) {
                final String status = version.path("status").asText("affected");
                if (version.hasNonNull("version")) {
                    if ("unaffected".equals(status)
                            && kernelVersion.equals(version.get("version").asText())) {
                        return false; // pinned to the exact fix release
                    }
                    continue;
                }
                if (!"affected".equals(status) || !version.hasNonNull("range")) {
                    continue;
                }
                if (rangeContains(version.get("range").asText(), kernelVersion)) {
                    affected = true;
                }
            }
        }
        return affected;
    }

    private static boolean rangeContains(final String range, final String version) {
        for (final String bound : range.trim().split("\\s+")) {
            if (bound.startsWith(">=")) {
                if (compareVersions(version, bound.substring(2)) < 0) return false;
            } else if (bound.startsWith("<")) {
                if (compareVersions(version, bound.substring(1)) >= 0) return false;
            }
        }
        return true;
    }

    /** Dotted-numeric comparison; non-numeric segments compare as 0. */
    static int compareVersions(final String a, final String b) {
        final String[] as = a.split("[^0-9]+"), bs = b.split("[^0-9]+");
        for (int i = 0; i < Math.max(as.length, bs.length); i++) {
            final long av = i < as.length && !as[i].isEmpty() ? Long.parseLong(as[i]) : 0;
            final long bv = i < bs.length && !bs[i].isEmpty() ? Long.parseLong(bs[i]) : 0;
            if (av != bv) {
                return Long.compare(av, bv);
            }
        }
        return 0;
    }

    /** {@code updated} of a feed JSON record (watermark filtering). */
    public Instant updatedOf(final JsonNode vuln) {
        return parseInstant(vuln.path("updated").asText(null));
    }

    /** {@code updated} of an emitted BOV (watermark advance in markProcessed). */
    Instant updatedOf(final Bom bov) {
        if (bov.getVulnerabilitiesCount() == 0 || !bov.getVulnerabilities(0).hasUpdated()) {
            return null;
        }
        final Timestamp ts = bov.getVulnerabilities(0).getUpdated();
        return Instant.ofEpochSecond(ts.getSeconds(), ts.getNanos());
    }

    // ── conversion helpers ───────────────────────────────────────────────────

    private VulnerabilityRating convertRating(final JsonNode rating) {
        if (!rating.hasNonNull("score")) {
            return null;
        }
        final var builder = VulnerabilityRating.newBuilder()
                .setScore(rating.get("score").asDouble());
        final String severity = rating.path("severity").asText("").toUpperCase(Locale.ROOT);
        builder.setSeverity(switch (severity) {
            case "CRITICAL" -> Severity.SEVERITY_CRITICAL;
            case "HIGH" -> Severity.SEVERITY_HIGH;
            case "MEDIUM" -> Severity.SEVERITY_MEDIUM;
            case "LOW" -> Severity.SEVERITY_LOW;
            case "INFO", "NONE" -> Severity.SEVERITY_INFO;
            default -> Severity.SEVERITY_UNKNOWN;
        });
        final String method = rating.path("method").asText("").toUpperCase(Locale.ROOT);
        if (method.contains("CVSSV4")) {
            builder.setMethod(ScoreMethod.SCORE_METHOD_CVSSV4);
        } else if (method.contains("CVSSV31")) {
            builder.setMethod(ScoreMethod.SCORE_METHOD_CVSSV31);
        } else if (method.contains("CVSSV3")) {
            builder.setMethod(ScoreMethod.SCORE_METHOD_CVSSV3);
        } else if (method.contains("CVSSV2")) {
            builder.setMethod(ScoreMethod.SCORE_METHOD_CVSSV2);
        }
        if (rating.hasNonNull("vector")) {
            builder.setVector(rating.get("vector").asText());
        }
        if (rating.path("source").hasNonNull("name")) {
            builder.setSource(Source.newBuilder()
                    .setName(rating.get("source").get("name").asText()));
        }
        return builder.build();
    }

    private VulnerabilityAffectedVersions convertVersion(final JsonNode version) {
        final var builder = VulnerabilityAffectedVersions.newBuilder();
        final String status = version.path("status").asText("affected");
        if (!"affected".equals(status)) {
            // Drop exact-version "unaffected" fix pins entirely: the affected
            // ranges already encode "< fix", and DT's BovModelConverter stores
            // ALL version entries as vulnerable=true VS rows regardless of
            // status — an "unaffected 6.6.121" pin became a row claiming
            // 6.6.121 IS vulnerable (observed live 2026-07-05).
            return null;
        }
        builder.setStatus(VulnerabilityAffectedStatus.VULNERABILITY_AFFECTED_STATUS_AFFECTED);
        if (version.hasNonNull("version")) {
            builder.setVersion(version.get("version").asText());
            return builder.build();
        }
        if (version.hasNonNull("range")) {
            // Feed emits ">=X <Y" / ">=X" / "<Y"; CycloneDX wants `vers`:
            // vers:generic/>=X|<Y
            final String feedRange = version.get("range").asText().trim();
            if (feedRange.isEmpty()) {
                return null;
            }
            builder.setRange("vers:generic/" + feedRange.replaceAll("\\s+", "|"));
            return builder.build();
        }
        return null;
    }

    private static Instant parseInstant(final String iso) {
        if (iso == null || iso.isEmpty()) {
            return null;
        }
        try {
            return Instant.parse(iso.replaceAll("\\+00:00$", "Z"));
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static Timestamp toTimestamp(final Instant instant) {
        return Timestamp.newBuilder()
                .setSeconds(instant.getEpochSecond())
                .setNanos(instant.getNano())
                .build();
    }

}
