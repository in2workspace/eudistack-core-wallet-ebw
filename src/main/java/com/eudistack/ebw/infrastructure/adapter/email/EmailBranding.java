package com.eudistack.ebw.infrastructure.adapter.email;

import java.util.List;

/**
 * Brand-specific items of a transactional email, already resolved to absolute URLs for a tenant.
 * {@code logoUrl} / {@code headerBackgroundUrl} are null when the tenant has no such image, and
 * {@code socialLinks} is empty when it has none: the templates then omit them.
 */
public record EmailBranding(
        String logoUrl,
        String headerBackgroundUrl,
        List<SocialLink> socialLinks
) {

    static final EmailBranding NONE = new EmailBranding(null, null, List.of());

    public record SocialLink(String type, String url) {
    }
}
