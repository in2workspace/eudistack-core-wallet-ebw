package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.TenantConfig;
import com.eudistack.ebw.domain.model.exception.TenantConfigMissingException;
import com.eudistack.ebw.domain.repository.TenantConfigRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TenantConfigService} — tenant-scoped cache (the tenant is part of the cache key, so two
 * tenants never share a value), defaults and the mandatory-key variant.
 */
@ExtendWith(MockitoExtension.class)
class TenantConfigServiceTest {

    private static final String KEY = "ebw.mail_from";

    @Mock private TenantConfigRepository repository;

    private TenantConfigService service;

    @BeforeEach
    void setUp() {
        service = new TenantConfigService(repository);
    }

    @Test
    void getString_sameTenantTwice_readsTheRepositoryOnce() {
        // Arrange
        when(repository.findByConfigKey(KEY)).thenReturn(Mono.just(config("wallet@sandbox.example")));

        // Act
        var first = service.getString(KEY).contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, "sandbox"));
        var second = service.getString(KEY).contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, "sandbox"));

        // Assert
        StepVerifier.create(first).expectNext("wallet@sandbox.example").verifyComplete();
        StepVerifier.create(second).expectNext("wallet@sandbox.example").verifyComplete();
        verify(repository, times(1)).findByConfigKey(KEY);
    }

    @Test
    void getString_differentTenants_doNotShareTheCachedValue() {
        // Arrange
        when(repository.findByConfigKey(KEY))
                .thenReturn(Mono.just(config("wallet@sandbox.example")))
                .thenReturn(Mono.just(config("wallet@kpmg.example")));

        // Act
        var sandbox = service.getString(KEY).contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, "sandbox"));
        var kpmg = service.getString(KEY).contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, "kpmg"));

        // Assert
        StepVerifier.create(sandbox).expectNext("wallet@sandbox.example").verifyComplete();
        StepVerifier.create(kpmg).expectNext("wallet@kpmg.example").verifyComplete();
        verify(repository, times(2)).findByConfigKey(KEY);
    }

    @Test
    void getStringOrDefault_missingKey_returnsTheDefault() {
        // Arrange
        when(repository.findByConfigKey(KEY)).thenReturn(Mono.empty());

        // Act
        var result = service.getStringOrDefault(KEY, "noreply@eudistack.com");

        // Assert
        StepVerifier.create(result).expectNext("noreply@eudistack.com").verifyComplete();
    }

    @Test
    void getStringOrThrow_missingKey_failsNamingTenantAndKey() {
        // Arrange
        when(repository.findByConfigKey(KEY)).thenReturn(Mono.empty());

        // Act
        var result = service.getStringOrThrow(KEY)
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, "sandbox"));

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof TenantConfigMissingException
                        && e.getMessage().contains("'" + KEY + "'") && e.getMessage().contains("'sandbox'"))
                .verify();
    }

    @Test
    void getStringOrThrow_presentKeyWithoutTenantInContext_returnsTheValue() {
        // Arrange
        when(repository.findByConfigKey(KEY)).thenReturn(Mono.just(config("value")));

        // Act
        var result = service.getStringOrThrow(KEY);

        // Assert
        StepVerifier.create(result).expectNext("value").verifyComplete();
    }

    private static TenantConfig config(String value) {
        return new TenantConfig(UUID.randomUUID(), KEY, value, null, Instant.now(), Instant.now());
    }
}
