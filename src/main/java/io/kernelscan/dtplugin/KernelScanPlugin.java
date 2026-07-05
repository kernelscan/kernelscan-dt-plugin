package io.kernelscan.dtplugin;

import io.kernelscan.dtplugin.source.KernelScanVulnDataSourceFactory;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.Plugin;

import java.util.Collection;
import java.util.List;

/**
 * KernelScan extensions for Dependency-Track v5.
 * <p>
 * Ships the {@code kernelscan} vulnerability data source (kernel CVE fastlane
 * + NVD enrichment). A config-aware {@code vuln-analyzer} extension may join
 * this list later — one plugin can contribute to multiple extension points.
 */
public final class KernelScanPlugin implements Plugin {

    @Override
    public Collection<? extends ExtensionFactory<? extends ExtensionPoint>> extensionFactories() {
        return List.of(new KernelScanVulnDataSourceFactory());
    }

}
