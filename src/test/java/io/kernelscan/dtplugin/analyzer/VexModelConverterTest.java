/*
 * Copyright (c) 2026 KernelScan UG (haftungsbeschränkt)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package io.kernelscan.dtplugin.analyzer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cyclonedx.proto.v1_7.Severity;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VexModelConverterTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final VexModelConverter converter = new VexModelConverter();

    private static JsonNode json(final String s) throws Exception {
        return MAPPER.readTree(s);
    }

    @Test
    void mapsCveUnderNvdIdentityWithMetadata() throws Exception {
        final JsonNode vuln = json("""
                {"id":"CVE-2023-53261","description":"desc","detail":"bpf UAF",
                 "cwes":[416],
                 "ratings":[{"score":7.8,"severity":"HIGH","method":"CVSSv31",
                             "vector":"CVSS:3.1/AV:L","source":{"name":"NVD"}}],
                 "published":"2023-01-02T00:00:00Z","updated":"2024-05-06T07:08:09+00:00"}
                """);

        final Vulnerability v = converter.toVulnerabilityBuilder(vuln, "CVE-2023-53261").build();

        assertEquals("CVE-2023-53261", v.getId());
        assertEquals("NVD", v.getSource().getName());
        assertEquals("desc", v.getDescription());
        assertEquals("bpf UAF", v.getDetail());
        assertEquals(416, v.getCwes(0));
        assertEquals(1, v.getRatingsCount());
        assertEquals(Severity.SEVERITY_HIGH, v.getRatings(0).getSeverity());
        assertEquals(7.8, v.getRatings(0).getScore(), 0.0001);
        assertTrue(v.hasPublished() && v.hasUpdated());
        assertTrue(v.getPropertiesList().stream()
                .anyMatch(p -> "dependency-track:vuln:reference-url".equals(p.getName())
                        && p.getValue().endsWith("CVE-2023-53261")));
    }

    @Test
    void ratingWithoutScoreIsDropped() throws Exception {
        final Vulnerability v = converter.toVulnerabilityBuilder(
                json("{\"id\":\"CVE-2024-0001\",\"ratings\":[{\"severity\":\"HIGH\"}]}"),
                "CVE-2024-0001").build();
        assertEquals(0, v.getRatingsCount());
    }

    @Test
    void parseInstantHandlesFormatsAndNull() {
        assertEquals(Instant.parse("2024-05-06T07:08:09Z"),
                VexModelConverter.parseInstant("2024-05-06T07:08:09+00:00"));
        assertEquals(Instant.parse("2023-01-02T00:00:00Z"),
                VexModelConverter.parseInstant("2023-01-02T00:00:00Z"));
        assertNull(VexModelConverter.parseInstant(null));
        assertNull(VexModelConverter.parseInstant("not-a-date"));
    }
}