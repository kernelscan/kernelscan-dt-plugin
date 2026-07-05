package io.kernelscan.dtplugin.source;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.dependencytrack.plugin.api.config.RuntimeConfig;

/**
 * Runtime configuration for the KernelScan vulnerability data source.
 * <p>
 * Hand-written equivalent of what upstream generates with jsonschema2pojo
 * (this repo builds with plain javac, no Maven codegen). MUST stay in sync
 * with {@code kernel-scan-vuln-data-source-config-v1.schema.json}, which is
 * resolved by naming convention (kebab-cased class name) and rendered as the
 * admin-UI config form.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class KernelScanVulnDataSourceConfigV1 implements RuntimeConfig {

    @JsonProperty("enabled")
    private boolean enabled;

    @JsonProperty("feedBaseUrl")
    private String feedBaseUrl;

    @JsonProperty("feedToken")
    private String feedToken;

    @JsonProperty("incrementalMirroringEnabled")
    private boolean incrementalMirroringEnabled = true;

    public boolean isEnabled() {
        return enabled;
    }

    public String getFeedBaseUrl() {
        return feedBaseUrl;
    }

    public String getFeedToken() {
        return feedToken;
    }

    public boolean isIncrementalMirroringEnabled() {
        return incrementalMirroringEnabled;
    }

    public KernelScanVulnDataSourceConfigV1 withEnabled(final boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    public KernelScanVulnDataSourceConfigV1 withFeedBaseUrl(final String feedBaseUrl) {
        this.feedBaseUrl = feedBaseUrl;
        return this;
    }

    public KernelScanVulnDataSourceConfigV1 withFeedToken(final String feedToken) {
        this.feedToken = feedToken;
        return this;
    }

    public KernelScanVulnDataSourceConfigV1 withIncrementalMirroringEnabled(final boolean incrementalMirroringEnabled) {
        this.incrementalMirroringEnabled = incrementalMirroringEnabled;
        return this;
    }

}
