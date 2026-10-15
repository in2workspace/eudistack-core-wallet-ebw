package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.TenantConfig;
import com.eudistack.ebw.domain.repository.TenantConfigRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.Mockito.when;

/** Unit tests for {@link WebAuthnRelyingPartyStartupCheck}. */
@ExtendWith(MockitoExtension.class)
class WebAuthnRelyingPartyStartupCheckTest {

    @Mock private ActiveTenantDirectory tenantDirectory;
    @Mock private TenantConfigRepository tenantConfigRepository;

    private WebAuthnRelyingPartyStartupCheck check;

    @BeforeEach
    void setUp() {
        check = new WebAuthnRelyingPartyStartupCheck(tenantDirectory, tenantConfigRepository);
    }

    @Test
    void tenantsWithoutRelyingParty_mixedTenants_reportsOnlyTheMissingOnes() {
        // Arrange
        when(tenantDirectory.activeTenants()).thenReturn(Flux.just("sandbox", "kpmg", "blank"));
        when(tenantConfigRepository.findByConfigKey("ebw.webauthn.rp_id")).thenReturn(Mono.deferContextual(ctx -> {
            String tenant = ctx.get(ReactorContextKeys.TENANT_DOMAIN);
            return switch (tenant) {
                case "sandbox" -> Mono.just(config("sandbox.stg.eudistack.net"));
                case "blank" -> Mono.just(config(" "));
                default -> Mono.empty();
            };
        }));

        // Act + Assert
        StepVerifier.create(check.tenantsWithoutRelyingParty())
                .expectNext(List.of("kpmg", "blank"))
                .verifyComplete();
    }

    @Test
    void tenantsWithoutRelyingParty_registryUnavailable_completesWithoutFailing() {
        // Arrange
        when(tenantDirectory.activeTenants()).thenReturn(Flux.error(new IllegalStateException("no registry")));

        // Act + Assert
        StepVerifier.create(check.tenantsWithoutRelyingParty()).expectNext(List.of()).verifyComplete();
    }

    private static TenantConfig config(String value) {
        return new TenantConfig(UUID.randomUUID(), "ebw.webauthn.rp_id", value, null, Instant.now(), Instant.now());
    }
}
