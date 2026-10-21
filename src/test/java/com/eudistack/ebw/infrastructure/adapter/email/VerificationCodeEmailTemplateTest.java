package com.eudistack.ebw.infrastructure.adapter.email;

import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import java.util.List;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/** Renders the real template with the real message bundle, outside Spring. */
class VerificationCodeEmailTemplateTest {

    private static final String ASSETS = "https://assets.example.com/assets/tenants";

    private static final EmailBranding DOME_BRANDING = new EmailBranding(
            ASSETS + "/dome/email/logo.png",
            ASSETS + "/dome/email/header-bg.png",
            List.of(
                    new EmailBranding.SocialLink("github", "https://github.com/dome-example"),
                    new EmailBranding.SocialLink("linkedin", "https://www.linkedin.com/company/dome-example")));

    private final SpringTemplateEngine engine = engine();

    @Test
    void render_withoutBranding_showsGreetingCodeBoxAndHintWithExpiry() {
        String html = render(EmailBranding.NONE, "Sandbox");

        assertThat(html)
                .doesNotContain("??")
                .contains("<title>Your Sandbox verification code — Wallet</title>")
                .contains("Hello,")
                .contains("Your verification code")
                .contains("background-color: #EBF0F7; border: 1px solid #8EACE1")
                .contains(">482193</span>")
                .contains("Enter this code in the Wallet. It expires in 10 minutes.")
                .contains("If you did not request this code, you can safely ignore this email.")
                .contains("family=Blinker")
                .doesNotContain("<img")
                .doesNotContain("background-image");
    }

    @Test
    void render_withBranding_showsLogoHeaderBackgroundAndSocialIcons() {
        String html = render(DOME_BRANDING, "DOME");

        assertThat(html)
                .contains("src=\"" + ASSETS + "/dome/email/logo.png\"")
                .contains("alt=\"DOME\"")
                .contains("background-image: url(" + ASSETS + "/dome/email/header-bg.png)")
                .contains("src=\"cid:icon-github.png\"")
                .contains("src=\"cid:icon-linkedin.png\"")
                .contains("href=\"https://github.com/dome-example\"");
    }

    private String render(EmailBranding branding, String tenantDisplayName) {
        Context context = new Context(Locale.ENGLISH);
        context.setVariable("txCode", "482193");
        context.setVariable("expirationMinutes", 10L);
        context.setVariable("branding", branding);
        context.setVariable("tenantDisplayName", tenantDisplayName);
        return engine.process("verification-code-email", context);
    }

    /** Real template engine and message bundle; also used by {@link SmtpEmailSenderTest}. */
    static SpringTemplateEngine engine() {
        ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
        messageSource.setBasename("messages");
        messageSource.setDefaultEncoding("UTF-8");
        messageSource.setFallbackToSystemLocale(false);

        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix("templates/");
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding("UTF-8");
        resolver.setCacheable(false);

        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolver(resolver);
        engine.setMessageSource(messageSource);
        return engine;
    }
}
