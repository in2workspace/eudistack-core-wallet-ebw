package com.eudistack.ebw.infrastructure.adapter.email;

import com.eudistack.ebw.infrastructure.adapter.properties.EmailBrandingProperties;
import com.eudistack.ebw.infrastructure.adapter.properties.EmailBrandingProperties.TenantEmailBranding;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/** Resolves the email branding of a tenant; tenants without a block get no images or social links. */
@Component
public class EmailBrandingResolver {

    private static final String LOGO_PATH = "email/logo.png";
    private static final String HEADER_BACKGROUND_PATH = "email/header-bg.png";

    private final EmailBrandingProperties properties;

    public EmailBrandingResolver(EmailBrandingProperties properties) {
        this.properties = properties;
    }

    public EmailBranding resolve(String tenantId) {
        TenantEmailBranding tenant = properties.tenants().get(tenantId);
        if (tenant == null) {
            return EmailBranding.NONE;
        }
        return new EmailBranding(
                tenant.logo() ? assetUrl(tenantId, LOGO_PATH) : null,
                tenant.headerBackground() ? assetUrl(tenantId, HEADER_BACKGROUND_PATH) : null,
                tenant.socialLinks().stream()
                        .map(link -> new EmailBranding.SocialLink(link.type(), link.url()))
                        .toList()
        );
    }

    private String assetUrl(String tenantId, String relativePath) {
        return StringUtils.trimTrailingCharacter(properties.assetsBaseUrl(), '/') + "/" + tenantId + "/" + relativePath;
    }
}
