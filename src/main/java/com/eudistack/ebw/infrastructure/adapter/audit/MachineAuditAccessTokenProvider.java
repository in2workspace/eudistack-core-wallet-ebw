package com.eudistack.ebw.infrastructure.adapter.audit;

import com.eudistack.auditoria.port.ReactiveAuditAccessTokenProvider;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientException;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Access token of the Wallet EBW for the Audit API, obtained as the system it is (DT-002 §3.8): the service
 * authenticates against the Verifier's token endpoint with its machine attestation ({@code client_credentials}
 * plus a {@code client_assertion}) and uses the token it gets until shortly before it expires. The bearer is
 * never configuration.
 *
 * <p>The audience cannot be requested: the Verifier puts its own URL in the {@code aud} of a machine token, so
 * that is the audience the Audit API has to expect.
 */
@Component
@ConditionalOnBooleanProperty("auditoria.dispatcher.enabled")
public class MachineAuditAccessTokenProvider implements ReactiveAuditAccessTokenProvider {

    private static final String X_TENANT_HEADER = "X-Tenant";
    private static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    /** The token is renewed this long before it expires, so the dispatcher never posts with one about to lapse. */
    private static final Duration EXPIRY_MARGIN = Duration.ofSeconds(60);
    /** Lifetime assumed when the response does not say; short on purpose. */
    private static final Duration DEFAULT_LIFETIME = Duration.ofMinutes(2);

    private final WebClient webClient;
    private final Clock clock;
    private final String tokenUrl;
    private final String tenant;
    private final String clientId;
    private final MachineClientAssertionFactory assertionFactory;
    private final AtomicReference<CachedToken> cached = new AtomicReference<>();

    @Autowired
    public MachineAuditAccessTokenProvider(
            @Value("${AUDIT_M2M_TOKEN_URL:}") String tokenUrl,
            @Value("${AUDIT_M2M_TENANT:}") String tenant,
            @Value("${AUDIT_M2M_CLIENT_ID:}") String clientId,
            @Value("${AUDIT_M2M_CREDENTIAL:}") String credential,
            @Value("${AUDIT_M2M_PRIVATE_KEY:}") String privateKey,
            @Value("${AUDIT_M2M_ASSERTION_AUDIENCE:}") String assertionAudience) {
        this(WebClient.create(), Clock.systemUTC(), tokenUrl, tenant, clientId,
                new MachineClientAssertionFactory(clientId, credential, privateKey, assertionAudience,
                        Clock.systemUTC()));
    }

    MachineAuditAccessTokenProvider(WebClient webClient, Clock clock, String tokenUrl, String tenant,
                                    String clientId, MachineClientAssertionFactory assertionFactory) {
        if (tokenUrl == null || tokenUrl.isBlank()) {
            throw new IllegalArgumentException("AUDIT_M2M_TOKEN_URL is not set");
        }
        if (tenant == null || tenant.isBlank()) {
            throw new IllegalArgumentException("AUDIT_M2M_TENANT is not set");
        }
        this.webClient = webClient;
        this.clock = clock;
        this.tokenUrl = tokenUrl;
        this.tenant = tenant;
        this.clientId = clientId;
        this.assertionFactory = assertionFactory;
    }

    @Override
    public Mono<String> accessToken(@Nullable String audience) {
        return Mono.defer(() -> {
            CachedToken current = cached.get();
            if (current != null && clock.instant().isBefore(current.renewAt())) {
                return Mono.just(current.value());
            }
            return renew();
        });
    }

    /** A 401 means the Audit API no longer accepts the token in hand: ask for a new one, whatever its expiry. */
    @Override
    public Mono<String> refreshAccessToken(@Nullable String audience) {
        return Mono.defer(this::renew);
    }

    private Mono<String> renew() {
        return requestToken().map(response -> {
            String token = response.path("access_token").asText(null);
            if (token == null || token.isBlank()) {
                throw new IllegalStateException("The Verifier answered without an access token for the Audit API");
            }
            Duration lifetime = response.hasNonNull("expires_in")
                    ? Duration.ofSeconds(response.get("expires_in").asLong())
                    : DEFAULT_LIFETIME;
            cached.set(new CachedToken(token, clock.instant().plus(lifetime).minus(EXPIRY_MARGIN)));
            return token;
        });
    }

    private Mono<JsonNode> requestToken() {
        return Mono.fromSupplier(assertionFactory::build)
                .flatMap(assertion -> webClient.post()
                        .uri(tokenUrl)
                        .header(X_TENANT_HEADER, tenant)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .body(BodyInserters.fromFormData(form(assertion)))
                        .retrieve()
                        .bodyToMono(JsonNode.class))
                // The response body is not logged or chained: it can echo the request.
                .onErrorMap(WebClientException.class, e -> new IllegalStateException(
                        "The Verifier did not issue an access token for the Audit API: "
                                + e.getClass().getSimpleName()));
    }

    private MultiValueMap<String, String> form(String assertion) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("client_assertion_type", CLIENT_ASSERTION_TYPE);
        form.add("client_assertion", assertion);
        return form;
    }

    private record CachedToken(String value, Instant renewAt) {
    }
}
