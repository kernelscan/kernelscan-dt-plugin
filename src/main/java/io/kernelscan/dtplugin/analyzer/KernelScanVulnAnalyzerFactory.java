package io.kernelscan.dtplugin.analyzer;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerFactory;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerRequirement;

import java.net.http.HttpClient;
import java.util.EnumSet;

/**
 * Factory for the {@code kernelscan} vulnerability analyzer — the
 * Snyk/VulnDB-style vendor slot. Matches Linux kernel components (purl or
 * CPE) and reports the kernel CVEs affecting their exact version, with
 * per-vulnerability identity {@code (CVE-*, NVD)} so findings merge with
 * DT's own NVD records and fastlane records are created under their final
 * identity (reconciliation honors the VDR's per-vuln source).
 */
public final class KernelScanVulnAnalyzerFactory implements VulnAnalyzerFactory, RuntimeConfigurable {

    private ConfigRegistry configRegistry;
    private HttpClient httpClient;
    private ObjectMapper objectMapper;

    @Override
    public String extensionName() {
        return "kernelscan";
    }

    @Override
    public Class<? extends VulnAnalyzer> extensionClass() {
        return KernelScanVulnAnalyzer.class;
    }

    @Override
    public void init(final ServiceRegistry serviceRegistry) {
        this.configRegistry = serviceRegistry.require(ConfigRegistry.class);
        this.httpClient = serviceRegistry.require(HttpClient.class);
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        final var defaultConfig = new KernelScanVulnAnalyzerConfigV1()
                .withEnabled(false)
                .withFeedBaseUrl("https://kernelscan.io/feed")
                .withFeedCacheMinutes(15);

        return RuntimeConfigSpec.of(defaultConfig, config -> {
            if (!config.isEnabled()) {
                return;
            }
            if (config.getFeedBaseUrl() == null || config.getFeedBaseUrl().isBlank()) {
                throw new InvalidRuntimeConfigException("No feed base URL provided");
            }
            if (config.getFeedToken() == null || config.getFeedToken().isBlank()) {
                throw new InvalidRuntimeConfigException("No feed token provided");
            }
        });
    }

    @Override
    public boolean isEnabled() {
        return configRegistry.getRuntimeConfig(KernelScanVulnAnalyzerConfigV1.class).isEnabled();
    }

    @Override
    public EnumSet<VulnAnalyzerRequirement> analyzerRequirements() {
        return EnumSet.of(
                VulnAnalyzerRequirement.COMPONENT_CPE,
                VulnAnalyzerRequirement.COMPONENT_PURL);
    }

    @Override
    public VulnAnalyzer create() {
        final var config = configRegistry.getRuntimeConfig(KernelScanVulnAnalyzerConfigV1.class);
        if (!config.isEnabled()) {
            throw new IllegalStateException("Analyzer is disabled and cannot be created");
        }
        return new KernelScanVulnAnalyzer(config, httpClient, objectMapper);
    }

}
