package com.eudistack.ebw.infrastructure.adapter.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Branding of the transactional emails, per tenant. Same file shape as eudistack-core-issuer's
 * {@code email-branding.yaml}, so one file can serve both services; the keys this service does not use
 * (the support and knowledge-base links) are ignored. Images and social links show only when the
 * tenant's own block enables them. Image locations are not configured: they follow the fixed names
 * {@code email/logo.png} and {@code email/header-bg.png} inside the tenant folder under
 * {@code assetsBaseUrl}.
 */
@ConfigurationProperties(prefix = "email-branding")
@Validated
public record EmailBrandingProperties(
        @NotBlank String assetsBaseUrl,
        @DefaultValue Map<String, @Valid TenantEmailBranding> tenants
) {

    public static final Set<String> SOCIAL_LINK_TYPES = Set.of("github", "linkedin");

    /**
     * A tenant's own branding. {@code logo} / {@code headerBackground} state that the tenant folder holds
     * that image; without them (or without a block) the email shows none.
     */
    public record TenantEmailBranding(
            @DefaultValue("false") boolean logo,
            @DefaultValue("false") boolean headerBackground,
            @DefaultValue List<@Valid SocialLink> socialLinks
    ) {
    }

    public record SocialLink(
            @NotBlank String type,
            @NotBlank String url
    ) {
        public SocialLink {
            if (type != null && !SOCIAL_LINK_TYPES.contains(type)) {
                throw new IllegalArgumentException(
                        "Unknown email-branding social link type '" + type + "'. Allowed: " + SOCIAL_LINK_TYPES);
            }
        }
    }
}
