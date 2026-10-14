package com.eudistack.ebw.infrastructure.adapter.email;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.core.io.ClassPathResource;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Writes the rendered verification-code email to {@code build/email-previews/*.html} for manual review in a
 * browser, without and with branding. Disabled by default; run with
 * {@code ./gradlew test --tests '*EmailPreviewGeneratorTest' -Demail.previews=true}.
 * <p>
 * The DOME variant loads the real logo and header background from {@code -Demail.previews.assets}
 * (default: the DEV environment's tenant assets). Inline {@code cid:} icons, which a browser cannot
 * resolve, are embedded as {@code data:} URIs.
 */
@EnabledIfSystemProperty(named = "email.previews", matches = "true")
class EmailPreviewGeneratorTest {

    private static final Path OUTPUT_DIR = Path.of("build", "email-previews");
    private static final String DEFAULT_ASSETS = "https://sandbox.dev.eudistack.net/assets/tenants";
    private static final Pattern CID = Pattern.compile("cid:icon-([\\w-]+)\\.png");

    @Test
    void generatePreviews() throws IOException {
        SpringTemplateEngine engine = VerificationCodeEmailTemplateTest.engine();
        Files.createDirectories(OUTPUT_DIR);

        String assets = stripTrailingSlashes(System.getProperty("email.previews.assets", DEFAULT_ASSETS));
        Map<String, EmailBranding> brandings = Map.of(
                "default", EmailBranding.NONE,
                "dome", new EmailBranding(
                        assets + "/dome/email/logo.png",
                        assets + "/dome/email/header-bg.png",
                        List.of(
                                new EmailBranding.SocialLink("github", "https://github.com/DOME-Marketplace"),
                                new EmailBranding.SocialLink("linkedin", "https://be.linkedin.com/company/dome-marketplace"))));

        for (Map.Entry<String, EmailBranding> brand : brandings.entrySet()) {
            Context context = new Context(Locale.ENGLISH);
            context.setVariable("txCode", "482193");
            context.setVariable("expirationMinutes", 10L);
            context.setVariable("branding", brand.getValue());
            context.setVariable("tenantDisplayName", brand.getKey().equals("dome") ? "DOME" : "EUDIStack Sandbox");
            String html = CID.matcher(engine.process("verification-code-email", context))
                    .replaceAll(match -> "data:image/png;base64," + Base64.getEncoder().encodeToString(icon(match.group(1))));
            Path preview = OUTPUT_DIR.resolve("verification-code-" + brand.getKey() + "-en.html");
            Files.writeString(preview, html, StandardCharsets.UTF_8);

            assertThat(Files.readString(preview, StandardCharsets.UTF_8))
                    .contains("482193")
                    .doesNotContain("cid:");
        }
    }

    private static String stripTrailingSlashes(String url) {
        int end = url.length();
        while (end > 0 && url.charAt(end - 1) == '/') {
            end--;
        }
        return url.substring(0, end);
    }

    private static byte[] icon(String name) {
        String path = "email/icons/" + name + ".png";
        try (InputStream in = new ClassPathResource(path).getInputStream()) {
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException("Missing email image: " + path, e);
        }
    }
}
