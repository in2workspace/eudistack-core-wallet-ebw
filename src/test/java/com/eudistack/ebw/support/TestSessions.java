package com.eudistack.ebw.support;

import org.mockito.stubbing.Answer;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;

import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Session claims for tests that mock {@code TokenSigner}. The JWT filter only accepts an access
 * token whose {@code tenant} claim is the request's tenant; tests that send the same mocked
 * bearer to several tenants record the tenant of each request with {@link #recordRequestTenant()}
 * and stub the signer with {@link #sessionOfRequestTenant}. The tenant check itself is covered by
 * {@code JwtAuthenticationWebFilterTest} and {@code SecurityWebFilterChainTest}.
 */
public final class TestSessions {

    private static final AtomicReference<String> REQUEST_TENANT = new AtomicReference<>();

    private TestSessions() {}

    public static Map<String, Object> claims(Object sub, String email, String tenant, UUID sessionId, UUID passkeyId) {
        return Map.of("sub", sub.toString(), "email", email, "tenant", tenant,
                "sid", sessionId.toString(), "pkid", passkeyId.toString());
    }

    public static Map<String, Object> claims(Object sub, String email, String tenant) {
        return claims(sub, email, tenant, UUID.randomUUID(), UUID.randomUUID());
    }

    /** Claims of a fixed session and passkey, in the tenant of the request being sent. */
    public static Answer<Map<String, Object>> sessionOfRequestTenant(Object sub, String email) {
        var sessionId = UUID.randomUUID();
        var passkeyId = UUID.randomUUID();
        return invocation -> claims(sub, email, REQUEST_TENANT.get(), sessionId, passkeyId);
    }

    /** WebTestClient filter that records the tenant of each request (X-Tenant, else first label of Host). */
    public static ExchangeFilterFunction recordRequestTenant() {
        return (request, next) -> {
            var tenant = request.headers().getFirst("X-Tenant");
            if (tenant == null) {
                var host = request.headers().getFirst("Host");
                tenant = host == null ? request.url().getHost() : host;
                tenant = tenant.split("[.:]")[0];
            }
            REQUEST_TENANT.set(tenant.trim().toLowerCase(Locale.ROOT));
            return next.exchange(request);
        };
    }
}
