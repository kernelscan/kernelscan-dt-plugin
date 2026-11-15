/*
 * Copyright (c) 2026 KernelScan UG (haftungsbeschränkt)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package io.kernelscan.dtplugin.analyzer;

import org.dependencytrack.plugin.api.ExtensionContext;

/** Dependency-Track 5.2.x flavour: {@code init(ExtensionContext)}. */
public final class KernelScanVulnAnalyzerFactory extends AbstractKernelScanVulnAnalyzerFactory {

    @Override
    public void init(final ExtensionContext context) {
        initServices(context.configRegistry(), context.httpClient());
    }

}
