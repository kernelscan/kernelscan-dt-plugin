package io.kernelscan.dtplugin.analyzer;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.protobuf.Timestamp;
import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.ScoreMethod;
import org.cyclonedx.proto.v1_7.Severity;
import org.cyclonedx.proto.v1_7.Source;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.cyclonedx.proto.v1_7.VulnerabilityRating;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Locale;

/**
 * Maps one vulnerability from a KernelScan product VEX
 * ({@code GET /api/products/{id}/vex}, CycloneDX JSON) into a CycloneDX
 * protobuf {@link Vulnerability.Builder} for the analyzer's VDR.
 * <p>
 * Identity is plain {@code CVE-*} with {@code source = NVD}, so findings and
 * any analyzer-introduced vulnerabilities share DT's canonical NVD identity
 * (no {@code KSCAN-*} namespacing, no duplicate findings). Affects entries are
 * added by the analyzer (it knows the concrete component bom-refs); this
 * converter produces the vulnerability metadata only.
 */
final class VexModelConverter {

    /**
     * Metadata-only proto vulnerability (id, source, description, CWE, CVSS
     * ratings, dates, reference URL) — no affects.
     */
    Vulnerability.Builder toVulnerabilityBuilder(final JsonNode vuln, final String cveId) {
        final var builder = Vulnerability.newBuilder()
                .setId(cveId)
                .setSource(Source.newBuilder()
                        .setName("NVD")
                        .setUrl("https://nvd.nist.gov/vuln/detail/" + cveId));

        if (vuln.hasNonNull("description")) {
            builder.setDescription(vuln.get("description").asText());
        }
        if (vuln.hasNonNull("detail")) {
            builder.setDetail(vuln.get("detail").asText()); // curated short name
        }
        for (final JsonNode cwe : vuln.path("cwes")) {
            builder.addCwes(cwe.asInt());
        }
        for (final JsonNode rating : vuln.path("ratings")) {
            final VulnerabilityRating converted = convertRating(rating);
            if (converted != null) {
                builder.addRatings(converted);
            }
        }
        final Instant published = parseInstant(vuln.path("published").asText(null));
        if (published != null) {
            builder.setPublished(toTimestamp(published));
        }
        final Instant updated = parseInstant(vuln.path("updated").asText(null));
        if (updated != null) {
            builder.setUpdated(toTimestamp(updated));
        }

        builder.addProperties(Property.newBuilder()
                .setName("dependency-track:vuln:reference-url")
                .setValue("https://kernelscan.io/cve/" + cveId));

        return builder;
    }

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

    static Instant parseInstant(final String iso) {
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
