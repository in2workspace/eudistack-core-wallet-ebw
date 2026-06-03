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
import java.util.Collections;
import java.util.List;

/**
 * Loads CORS allowed origins from a YAML file (mirrors issuer-core pattern).
 * External path configured via APP_CORS_ORIGINS_PATH (EFS mount in STG).
 * Falls back to classpath cors-origins.yaml, then to ebw.cors.allowed-origins.
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
        try (InputStream is = openInputStream()) {
            if (is == null) {
                return parseFallback();
            }
            CorsOriginsData data = yamlMapper.readValue(is, CorsOriginsData.class);
            if (data.getOrigins() == null || data.getOrigins().isEmpty()) {
                return parseFallback();
            }
            List<String> origins = data.getOrigins().stream()
                    .map(CorsOriginsData.OriginEntry::getUrl)
                    .filter(url -> url != null && !url.isBlank())
                    .toList();
            log.info("Loaded {} CORS origins from cors-origins.yaml", origins.size());
            return origins;
        } catch (IOException e) {
            log.warn("Failed to read cors-origins.yaml — using fallback origins: {}", e.getMessage());
            return parseFallback();
        }
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

    private List<String> parseFallback() {
        if (fallbackOrigins != null && !fallbackOrigins.isBlank()) {
            List<String> origins = List.of(fallbackOrigins.split(","));
            log.info("Using fallback CORS origins: {}", origins);
            return origins;
        }
        return Collections.emptyList();
    }
}
