package io.kernelscan.dtplugin;

import io.kernelscan.dtplugin.analyzer.KernelScanVulnAnalyzerFactory;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.Plugin;

import java.util.Collection;
import java.util.List;

/**
 * KernelScan plugin for Dependency-Track v5.
 * <p>
 * Registers the {@code kernelscan} vulnerability analyzer — config-aware Linux
 * kernel CVE findings, matched by kernel version/CPE and filtered to what is
 * reachable in the customer's {@code .config}. Discovered via ServiceLoader
 * ({@code META-INF/services/org.dependencytrack.plugin.api.Plugin}) when the
 * JAR is on the apiserver classpath.
 */
public final class KernelScanPlugin implements Plugin {

    @Override
    public Collection<? extends ExtensionFactory<? extends ExtensionPoint>> extensionFactories() {
        return List.of(new KernelScanVulnAnalyzerFactory());
    }

}
