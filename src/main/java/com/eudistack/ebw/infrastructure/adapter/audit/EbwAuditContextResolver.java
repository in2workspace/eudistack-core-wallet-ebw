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

import java.util.regex.Pattern;

/**
 * Tells the audit starter who is acting in a request: the tenant the tenant filter resolved and the wallet
 * itself as a system, since what it audits (the mail it sends) is its own action. A request without a
 * tenant has no context.
 *
 * <p>The correlation id is the trace id of the request ({@code traceparent}, W3C) when it carries one, so the
 * events of one request, and of the others in the same trace, can be linked. Without one the starter gives each
 * event its own.
 */
@Component
@ConditionalOnBooleanProperty("auditoria.publisher.enabled")
public class EbwAuditContextResolver implements ReactiveAuditContextResolver {

    private static final String TRACEPARENT_HEADER = "traceparent";
    private static final Pattern TRACEPARENT = Pattern.compile("^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$");

    @Override
    public Mono<AuditContext> resolve(ServerWebExchange exchange, @Nullable Authentication authentication) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "");
            if (tenant.isBlank()) {
                return Mono.empty();
            }
            return Mono.just(new AuditContext(tenant, null, traceIdOf(exchange),
                    AuditActor.system(AuditSource.WALLET_EBW)));
        });
    }

    /** The trace id of a well-formed {@code traceparent} (version-traceid-spanid-flags), or {@code null}. */
    private static String traceIdOf(ServerWebExchange exchange) {
        String traceparent = exchange.getRequest().getHeaders().getFirst(TRACEPARENT_HEADER);
        if (traceparent == null) {
            return null;
        }
        var matcher = TRACEPARENT.matcher(traceparent.trim());
        return matcher.matches() ? matcher.group(1) : null;
    }
}
