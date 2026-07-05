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

    @JsonProperty("feedBaseUrl")
    private String feedBaseUrl;

    @JsonProperty("feedToken")
    private String feedToken;

    @JsonProperty("feedCacheMinutes")
    private int feedCacheMinutes = 15;

    public boolean isEnabled() {
        return enabled;
    }

    public String getFeedBaseUrl() {
        return feedBaseUrl;
    }

    public String getFeedToken() {
        return feedToken;
    }

    public int getFeedCacheMinutes() {
        return feedCacheMinutes;
    }

    public KernelScanVulnAnalyzerConfigV1 withEnabled(final boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    public KernelScanVulnAnalyzerConfigV1 withFeedBaseUrl(final String feedBaseUrl) {
        this.feedBaseUrl = feedBaseUrl;
        return this;
    }

    public KernelScanVulnAnalyzerConfigV1 withFeedToken(final String feedToken) {
        this.feedToken = feedToken;
        return this;
    }

    public KernelScanVulnAnalyzerConfigV1 withFeedCacheMinutes(final int feedCacheMinutes) {
        this.feedCacheMinutes = feedCacheMinutes;
        return this;
    }

}
