package com.eudistack.ebw.infrastructure.adapter.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The tenant's Verifier, issuer of the system tokens accepted by {@code POST /onboarding-tickets}
 * (EUD-315, design §2.6).
 *
 * @param internalUrl internal base URL of the Verifier, with its base path (for instance
 *                    {@code http://verifier-service:8080/verifier}); discovery and JWKS are read
 *                    from it. Blank: no system token is accepted (503).
 * @param basePath    public base path of the Verifier on the tenant host (read by
 *                    {@code SystemTokenWebFilter}): the expected {@code iss} of a system token is the
 *                    public origin of the request plus this path, as the Issuer does
 *                    ({@code UrlResolver.expectedVerifierBaseUrls}).
 */
@ConfigurationProperties(prefix = "ebw.verifier")
public record VerifierProperties(String internalUrl, String basePath) {

    public VerifierProperties {
        internalUrl = internalUrl == null ? "" : internalUrl.trim();
        basePath = basePath == null || basePath.isBlank() ? "/verifier" : basePath.trim();
    }

    public boolean configured() {
        return !internalUrl.isEmpty();
    }
}
