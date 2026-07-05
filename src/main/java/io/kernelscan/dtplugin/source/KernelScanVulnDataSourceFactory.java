package io.kernelscan.dtplugin.source;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;

import java.net.http.HttpClient;

/**
 * Factory for the {@code kernelscan} vulnerability data source.
 * <p>
 * Mirrors the upstream pattern (see {@code OsvVulnDataSourceFactory}):
 * runtime config is a typed POJO backed by a JSON schema resource that
 * doubles as the admin-UI form; services (config registry, KV store for
 * watermarks, JDK HttpClient) are injected via the {@link ServiceRegistry}.
 */
public final class KernelScanVulnDataSourceFactory implements VulnDataSourceFactory, RuntimeConfigurable {

    private ConfigRegistry configRegistry;
    private KeyValueStore kvStore;
    private HttpClient httpClient;
    private ObjectMapper objectMapper;

    @Override
    public String extensionName() {
        return "kernelscan";
    }

    @Override
    public Class<? extends VulnDataSource> extensionClass() {
        return KernelScanVulnDataSource.class;
    }

    @Override
    public int priority() {
        // After the bundled sources (osv is PRIORITY_HIGHEST + 100) — NVD/OSV
        // records land first, ours enrich/extend in the same mirror pass.
        return PRIORITY_HIGHEST + 110;
    }

    @Override
    public void init(final ServiceRegistry serviceRegistry) {
        this.configRegistry = serviceRegistry.require(ConfigRegistry.class);
        this.kvStore = serviceRegistry.require(KeyValueStore.class);
        this.httpClient = serviceRegistry.require(HttpClient.class);
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        final var defaultConfig = new KernelScanVulnDataSourceConfigV1()
                .withEnabled(false)
                .withFeedBaseUrl("https://kernelscan.io/feed")
                .withIncrementalMirroringEnabled(true);

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
    public boolean isDataSourceEnabled() {
        return configRegistry.getRuntimeConfig(KernelScanVulnDataSourceConfigV1.class).isEnabled();
    }

    @Override
    public VulnDataSource create() {
        final var config = configRegistry.getRuntimeConfig(KernelScanVulnDataSourceConfigV1.class);
        if (!config.isEnabled()) {
            throw new IllegalStateException("Vulnerability data source is disabled and cannot be created");
        }
        return new KernelScanVulnDataSource(config, httpClient, objectMapper, kvStore);
    }

}
