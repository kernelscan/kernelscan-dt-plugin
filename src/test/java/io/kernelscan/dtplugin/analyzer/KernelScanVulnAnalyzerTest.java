/*
 * Copyright (c) 2026 KernelScan UG (haftungsbeschränkt)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package io.kernelscan.dtplugin.analyzer;

import org.cyclonedx.proto.v1_7.Component;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class KernelScanVulnAnalyzerTest {

    private static Component cpe(final String cpe) {
        return Component.newBuilder().setName("linux").setCpe(cpe).build();
    }

    private static Component purl(final String purl) {
        return Component.newBuilder().setName("kernel").setPurl(purl).build();
    }

    @Test
    void versionFromCpe() {
        assertEquals("5.15.102",
                KernelScanVulnAnalyzer.kernelVersionOf(cpe("cpe:2.3:o:linux:linux_kernel:5.15.102:*:*:*:*:*:*:*")));
    }

    @Test
    void wildcardCpeVersionIsIgnored() {
        assertNull(KernelScanVulnAnalyzer.kernelVersionOf(cpe("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*")));
    }

    @Test
    void versionFromPurl() {
        assertEquals("6.6.69",
                KernelScanVulnAnalyzer.kernelVersionOf(purl("pkg:generic/linux/kernel@6.6.69")));
        assertEquals("6.1.86",
                KernelScanVulnAnalyzer.kernelVersionOf(purl("pkg:generic/linux/kernel@6.1.86?arch=x86_64")));
    }

    @Test
    void productBindingReadFromProperty() {
        final Component c = Component.newBuilder().setName("linux")
                .setCpe("cpe:2.3:o:linux:linux_kernel:6.6.69:*:*:*:*:*:*:*")
                .addProperties(org.cyclonedx.proto.v1_7.Property.newBuilder()
                        .setName("kernelscan:product").setValue("Router-A [6.6.69]"))
                .build();
        assertEquals("Router-A [6.6.69]", KernelScanVulnAnalyzer.productBindingOf(c));
    }

    @Test
    void noBindingWhenPropertyAbsentOrBlank() {
        assertNull(KernelScanVulnAnalyzer.productBindingOf(
                Component.newBuilder().setName("linux").build()));
        assertNull(KernelScanVulnAnalyzer.productBindingOf(Component.newBuilder().setName("linux")
                .addProperties(org.cyclonedx.proto.v1_7.Property.newBuilder()
                        .setName("kernelscan:product").setValue("  "))
                .build()));
    }

    @Test
    void nonKernelComponentIsIgnored() {
        assertNull(KernelScanVulnAnalyzer.kernelVersionOf(
                cpe("cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*")));
        assertNull(KernelScanVulnAnalyzer.kernelVersionOf(
                purl("pkg:deb/debian/bash@5.2.15")));
        assertNull(KernelScanVulnAnalyzer.kernelVersionOf(
                Component.newBuilder().setName("linux").build())); // no cpe/purl
    }
}