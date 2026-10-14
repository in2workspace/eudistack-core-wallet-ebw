package com.eudistack.ebw.infrastructure.adapter.email;

import com.eudistack.ebw.infrastructure.adapter.properties.EmailBrandingProperties;
import com.eudistack.ebw.infrastructure.adapter.properties.EmailBrandingProperties.SocialLink;
import com.eudistack.ebw.infrastructure.adapter.properties.EmailBrandingProperties.TenantEmailBranding;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EmailBrandingResolverTest {

    private static final String ASSETS = "https://assets.example.com/assets/tenants/";

    private final EmailBrandingResolver resolver = new EmailBrandingResolver(new EmailBrandingProperties(ASSETS, Map.of(
            "dome", new TenantEmailBranding(true, true, List.of(new SocialLink("github", "https://github.com/dome"))),
            "acme", new TenantEmailBranding(false, true, List.of()))));

    @Test
    void resolve_tenantWithBlock_buildsImageUrlsByConventionAndMapsSocialLinks() {
        EmailBranding branding = resolver.resolve("dome");

        assertThat(branding.logoUrl()).isEqualTo("https://assets.example.com/assets/tenants/dome/email/logo.png");
        assertThat(branding.headerBackgroundUrl()).isEqualTo("https://assets.example.com/assets/tenants/dome/email/header-bg.png");
        assertThat(branding.socialLinks()).containsExactly(new EmailBranding.SocialLink("github", "https://github.com/dome"));
    }

    @Test
    void resolve_imageFlagOff_leavesThatImageOut() {
        EmailBranding branding = resolver.resolve("acme");

        assertThat(branding.logoUrl()).isNull();
        assertThat(branding.headerBackgroundUrl()).endsWith("/acme/email/header-bg.png");
    }

    @Test
    void resolve_tenantWithoutBlock_hasNoImagesNorSocialLinks() {
        assertThat(resolver.resolve("sandbox")).isEqualTo(EmailBranding.NONE);
        assertThat(resolver.resolve("")).isEqualTo(EmailBranding.NONE);
    }

    @Test
    void socialLink_unknownType_isRejected() {
        assertThatThrownBy(() -> new SocialLink("twitter", "https://x.com/dome"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("twitter");
    }
}
