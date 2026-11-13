package com.eudistack.ebw.infrastructure.adapter.audit;

import com.eudistack.auditoria.domain.AuditActor;
import com.eudistack.auditoria.domain.AuditContext;
import com.eudistack.auditoria.port.ReactiveAuditContextResolver;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.audit.AuditSource;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Tells the audit starter who is acting in a request: the tenant the tenant filter resolved and the wallet
 * itself as a system, since what it audits (the mail it sends) is its own action. A request without a
 * tenant has no context.
 */
@Component
@ConditionalOnBooleanProperty("auditoria.publisher.enabled")
public class EbwAuditContextResolver implements ReactiveAuditContextResolver {

    @Override
    public Mono<AuditContext> resolve(ServerWebExchange exchange, @Nullable Authentication authentication) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "");
            if (tenant.isBlank()) {
                return Mono.empty();
            }
            return Mono.just(new AuditContext(tenant, null, null, AuditActor.system(AuditSource.WALLET_EBW)));
        });
    }
}
