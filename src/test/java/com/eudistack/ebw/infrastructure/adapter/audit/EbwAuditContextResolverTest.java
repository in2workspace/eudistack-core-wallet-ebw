package com.eudistack.ebw.infrastructure.adapter.audit;

import com.eudistack.auditoria.domain.ActorKind;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EbwAuditContextResolverTest {

    private final EbwAuditContextResolver resolver = new EbwAuditContextResolver();
    private final MockServerWebExchange exchange =
            MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/auth/register"));

    @Test
    void resolve_requestWithTenant_isTheWalletAsASystemInThatTenant() {
        // Arrange & Act & Assert
        StepVerifier.create(resolver.resolve(exchange, null)
                        .contextWrite(Context.of(ReactorContextKeys.TENANT_DOMAIN, "sandbox")))
                .assertNext(context -> {
                    assertEquals("sandbox", context.tenant());
                    assertEquals(ActorKind.SYSTEM, context.actor().kind());
                    assertEquals("wallet-ebw", context.actor().id());
                })
                .verifyComplete();
    }

    @Test
    void resolve_requestWithoutTenant_hasNoContext() {
        // Arrange & Act & Assert
        StepVerifier.create(resolver.resolve(exchange, null)).verifyComplete();
    }

    @Test
    void resolve_requestWithATraceparent_usesItsTraceIdAsTheCorrelationOfTheEvents() {
        // Arrange
        MockServerWebExchange traced = MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/auth/register")
                .header("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"));

        // Act & Assert
        StepVerifier.create(resolver.resolve(traced, null)
                        .contextWrite(Context.of(ReactorContextKeys.TENANT_DOMAIN, "sandbox")))
                .assertNext(context -> assertEquals("0af7651916cd43dd8448eb211c80319c", context.correlationId()))
                .verifyComplete();
    }

    @Test
    void resolve_requestWithAMalformedTraceparent_leavesTheCorrelationToTheStarter() {
        // Arrange
        MockServerWebExchange traced = MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/auth/register")
                .header("traceparent", "not-a-traceparent\r\ninjected"));

        // Act & Assert
        StepVerifier.create(resolver.resolve(traced, null)
                        .contextWrite(Context.of(ReactorContextKeys.TENANT_DOMAIN, "sandbox")))
                .assertNext(context -> org.junit.jupiter.api.Assertions.assertNull(context.correlationId()))
                .verifyComplete();
    }
}
