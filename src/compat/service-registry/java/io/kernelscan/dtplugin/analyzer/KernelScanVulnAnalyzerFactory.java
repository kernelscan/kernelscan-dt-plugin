/*
 * Copyright (c) 2026 KernelScan UG (haftungsbeschränkt)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package io.kernelscan.dtplugin.analyzer;

import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;

import java.net.http.HttpClient;

/** Dependency-Track 5.0.x / 5.1.x flavour: {@code init(ServiceRegistry)}. */
public final class KernelScanVulnAnalyzerFactory extends AbstractKernelScanVulnAnalyzerFactory {

    @Override
    public void init(final ServiceRegistry serviceRegistry) {
        initServices(serviceRegistry.require(ConfigRegistry.class), serviceRegistry.require(HttpClient.class));
    }

}
