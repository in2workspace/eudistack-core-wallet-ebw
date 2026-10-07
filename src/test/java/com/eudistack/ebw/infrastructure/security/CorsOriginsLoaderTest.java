package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.infrastructure.adapter.properties.CorsProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link CorsOriginsLoader} — external YAML file first, then the classpath default
 * (absent in this repo), then the comma-separated {@code ebw.cors.allowed-origins} fallback.
 */
class CorsOriginsLoaderTest {

    private static final String FALLBACK = "http://localhost:4200,https://wallet.example";

    @TempDir
    Path tempDir;

    @Test
    void loadOrigins_externalFileWithOrigins_returnsTheirNonBlankUrls() throws IOException {
        // Arrange
        var file = writeYaml("""
                origins:
                  - url: https://sandbox.wallet.example
                    tenant: sandbox
                  - url: https://kpmg.wallet.example
                    tenant: kpmg
                  - url: "  "
                  - tenant: no-url
                """);
        var loader = new CorsOriginsLoader(new CorsProperties(FALLBACK, file.toString()));

        // Act
        var origins = loader.loadOrigins();

        // Assert
        assertThat(origins).containsExactly("https://sandbox.wallet.example", "https://kpmg.wallet.example");
    }

    @Test
    void loadOrigins_externalFileWithoutOrigins_usesFallback() throws IOException {
        // Arrange
        var file = writeYaml("origins: []\n");
        var loader = new CorsOriginsLoader(new CorsProperties(FALLBACK, file.toString()));

        // Act
        var origins = loader.loadOrigins();

        // Assert
        assertThat(origins).containsExactly("http://localhost:4200", "https://wallet.example");
    }

    @Test
    void loadOrigins_externalFileWithNullOrigins_usesFallback() throws IOException {
        // Arrange
        var file = writeYaml("other: value\n");
        var loader = new CorsOriginsLoader(new CorsProperties(FALLBACK, file.toString()));

        // Act
        var origins = loader.loadOrigins();

        // Assert
        assertThat(origins).containsExactly("http://localhost:4200", "https://wallet.example");
    }

    @Test
    void loadOrigins_unreadableYaml_usesFallback() throws IOException {
        // Arrange
        var file = writeYaml("origins: [unclosed\n");
        var loader = new CorsOriginsLoader(new CorsProperties(FALLBACK, file.toString()));

        // Act
        var origins = loader.loadOrigins();

        // Assert
        assertThat(origins).containsExactly("http://localhost:4200", "https://wallet.example");
    }

    @Test
    void loadOrigins_externalFileMissingAndNoClasspathDefault_usesFallback() {
        // Arrange
        var loader = new CorsOriginsLoader(new CorsProperties(FALLBACK, tempDir.resolve("absent.yaml").toString()));

        // Act
        var origins = loader.loadOrigins();

        // Assert
        assertThat(origins).containsExactly("http://localhost:4200", "https://wallet.example");
    }

    @Test
    void loadOrigins_noFileAndBlankFallback_returnsEmptyList() {
        // Arrange
        var loader = new CorsOriginsLoader(new CorsProperties(" ", " "));

        // Act
        var origins = loader.loadOrigins();

        // Assert
        assertThat(origins).isEmpty();
    }

    @Test
    void loadOrigins_nullProperties_returnsEmptyList() {
        // Arrange
        var loader = new CorsOriginsLoader(null);

        // Act
        var origins = loader.loadOrigins();

        // Assert
        assertThat(origins).isEmpty();
    }

    private Path writeYaml(String content) throws IOException {
        var file = tempDir.resolve("cors-origins.yaml");
        Files.writeString(file, content);
        return file;
    }
}
