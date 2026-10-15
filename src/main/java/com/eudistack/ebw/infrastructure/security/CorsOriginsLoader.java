package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.infrastructure.adapter.properties.CorsProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * Loads the CORS allowed origins (mirrors issuer-core pattern).
 *
 * <p>The allowed origins are the union, without duplicates, of the origins in
 * {@code cors-origins.yaml} (external path {@code APP_CORS_ORIGINS_PATH}, EFS mount in STG,
 * or the classpath file) and of {@code ebw.cors.allowed-origins} ({@code CORS_ORIGINS}). Both
 * sources are used because in STG the file only holds legacy origins while the tenant origins
 * come from the environment variable.
 */
@Slf4j
@Component
public class CorsOriginsLoader {

    private static final String CLASSPATH_DEFAULT = "cors-origins.yaml";
    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
    private final String externalPath;
    private final String fallbackOrigins;

    public CorsOriginsLoader(CorsProperties corsProperties) {
        this.externalPath = corsProperties != null ? corsProperties.originsPath() : null;
        this.fallbackOrigins = corsProperties != null ? corsProperties.allowedOrigins() : null;
    }

    public List<String> loadOrigins() {
        var origins = new LinkedHashSet<String>();
        origins.addAll(fileOrigins());
        origins.addAll(propertyOrigins());
        log.info("Loaded {} CORS origins", origins.size());
        return List.copyOf(origins);
    }

    private List<String> fileOrigins() {
        try (InputStream is = openInputStream()) {
            if (is == null) {
                return List.of();
            }
            CorsOriginsData data = yamlMapper.readValue(is, CorsOriginsData.class);
            if (data == null || data.getOrigins() == null) {
                return List.of();
            }
            return data.getOrigins().stream()
                    .map(CorsOriginsData.OriginEntry::getUrl)
                    .filter(url -> url != null && !url.isBlank())
                    .map(String::trim)
                    .toList();
        } catch (IOException e) {
            log.warn("Failed to read cors-origins.yaml: {}", e.getMessage());
            return List.of();
        }
    }

    private List<String> propertyOrigins() {
        if (fallbackOrigins == null || fallbackOrigins.isBlank()) {
            return List.of();
        }
        return Arrays.stream(fallbackOrigins.split(","))
                .map(String::trim)
                .filter(origin -> !origin.isEmpty())
                .toList();
    }

    private InputStream openInputStream() throws IOException {
        if (externalPath != null && !externalPath.isBlank()) {
            Path path = Path.of(externalPath);
            if (Files.exists(path)) {
                log.info("Loading CORS origins from external file: {}", externalPath);
                return new FileInputStream(path.toFile());
            }
            log.warn("External CORS origins file not found: {}. Falling back to classpath.", externalPath);
        }
        InputStream is = getClass().getClassLoader().getResourceAsStream(CLASSPATH_DEFAULT);
        if (is != null) {
            log.info("Loading CORS origins from classpath: {}", CLASSPATH_DEFAULT);
        }
        return is;
    }
}
