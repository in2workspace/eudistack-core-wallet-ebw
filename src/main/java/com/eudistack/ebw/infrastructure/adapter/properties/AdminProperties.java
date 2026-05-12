package com.eudistack.ebw.infrastructure.adapter.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for the admin write API (the {@code /admin/**} endpoints).
 *
 * <p>Bound from the {@code ebw.admin} prefix in {@code application.yaml}. The API key is injected
 * via the {@code ADMIN_API_KEY} environment variable (an SSM parameter in STG; a plain dev
 * placeholder in local Docker Compose).
 *
 * <p><strong>Fail-closed:</strong> when {@code apiKey} is blank, {@code null} or unset the admin
 * filter rejects <em>all</em> {@code /admin/**} requests with HTTP 401 — there is no implicit
 * "no key configured ⇒ open" mode. See {@code AdminApiKeyAuthenticationWebFilter} and SEC-B2.
 */
@ConfigurationProperties(prefix = "ebw.admin")
public record AdminProperties(String apiKey) {
}
