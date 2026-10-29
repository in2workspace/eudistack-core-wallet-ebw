package com.eudistack.ebw.infrastructure.adapter.audit;

import com.eudistack.auditoria.port.ReactiveAuditAccessTokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Interim access token of the Wallet EBW for the Audit API, read from {@code AUDIT_API_ACCESS_TOKEN}. It lets
 * the dispatcher run against a local Audit API (its {@code devTokens}). The token a deployed Wallet EBW needs,
 * with the power {@code organization · EUDISTACK · Audit · Write}, has to be obtained with its system
 * credentials; that is not built yet.
 */
@Component
@ConditionalOnBooleanProperty("auditoria.dispatcher.enabled")
public class ConfiguredAuditAccessTokenProvider implements ReactiveAuditAccessTokenProvider {

    private final String accessToken;

    public ConfiguredAuditAccessTokenProvider(@Value("${AUDIT_API_ACCESS_TOKEN:}") String accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public Mono<String> accessToken(@Nullable String audience) {
        if (accessToken.isBlank()) {
            return Mono.error(new IllegalStateException("AUDIT_API_ACCESS_TOKEN is not set"));
        }
        return Mono.just(accessToken);
    }

    @Override
    public Mono<String> refreshAccessToken(@Nullable String audience) {
        return accessToken(audience);
    }
}
