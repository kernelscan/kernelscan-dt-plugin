package io.kernelscan.dtplugin;

import io.kernelscan.dtplugin.analyzer.KernelScanVulnAnalyzerFactory;
import io.kernelscan.dtplugin.source.KernelScanVulnDataSourceFactory;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.Plugin;

import java.util.Collection;
import java.util.List;

/**
 * KernelScan extensions for Dependency-Track v5.
 * <p>
 * Ships two extensions:
 * <ul>
 *   <li>{@code vuln-analyzer/kernelscan} — the working path today: per-project
 *       kernel CVE findings with (CVE-*, NVD) identity; fastlane records are
 *       created via analyzer reconciliation (per-vuln VDR source honored).</li>
 *   <li>{@code vuln-data-source/kernelscan} — DB-wide mirror; BLOCKED in DT
 *       5.0.2 (sourceName is derived as uppercase(extensionName) and must be
 *       a known Vulnerability.Source enum value). Kept for the upstream fix;
 *       see repo issue #1.</li>
 * </ul>
 */
public final class KernelScanPlugin implements Plugin {

    @Override
    public Collection<? extends ExtensionFactory<? extends ExtensionPoint>> extensionFactories() {
        return List.of(
                new KernelScanVulnAnalyzerFactory(),
                new KernelScanVulnDataSourceFactory());
    }

}
