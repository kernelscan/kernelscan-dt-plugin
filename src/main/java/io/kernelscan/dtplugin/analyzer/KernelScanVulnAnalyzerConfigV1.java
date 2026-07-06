package io.kernelscan.dtplugin.analyzer;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.dependencytrack.plugin.api.config.RuntimeConfig;

/**
 * Runtime configuration for the KernelScan vulnerability analyzer.
 * Kept in sync with {@code kernel-scan-vuln-analyzer-config-v1.schema.json}
 * (kebab-case naming convention; renders as the admin-UI form).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class KernelScanVulnAnalyzerConfigV1 implements RuntimeConfig {

    @JsonProperty("enabled")
    private boolean enabled;

    // ── config-aware "product mode" (the customer setup) ─────────────────────
    // Resolves the customer's KernelScan product for the kernel under analysis
    // and reports its config-aware finding set (CVEs reachable in that .config).

    @JsonProperty("apiBaseUrl")
    private String apiBaseUrl = "https://kernelscan.io";

    @JsonProperty("apiKey")
    private String apiKey;

    @JsonProperty("arch")
    private String arch = "x86_64";

    @JsonProperty("cacheMinutes")
    private int cacheMinutes = 15;

    public boolean isEnabled() {
        return enabled;
    }

    public String getApiBaseUrl() {
        return apiBaseUrl;
    }

    public String getApiKey() {
        return apiKey;
    }

    public String getArch() {
        return arch;
    }

    public int getCacheMinutes() {
        return cacheMinutes;
    }

    public KernelScanVulnAnalyzerConfigV1 withEnabled(final boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    public KernelScanVulnAnalyzerConfigV1 withApiBaseUrl(final String apiBaseUrl) {
        this.apiBaseUrl = apiBaseUrl;
        return this;
    }

    public KernelScanVulnAnalyzerConfigV1 withApiKey(final String apiKey) {
        this.apiKey = apiKey;
        return this;
    }

    public KernelScanVulnAnalyzerConfigV1 withArch(final String arch) {
        this.arch = arch;
        return this;
    }

    public KernelScanVulnAnalyzerConfigV1 withCacheMinutes(final int cacheMinutes) {
        this.cacheMinutes = cacheMinutes;
        return this;
    }

}
