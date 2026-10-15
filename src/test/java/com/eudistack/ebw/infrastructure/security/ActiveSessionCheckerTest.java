package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.service.AuthTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link ActiveSessionChecker}. */
@ExtendWith(MockitoExtension.class)
class ActiveSessionCheckerTest {

    private static final String TENANT = "sandbox";

    @Mock
    private AuthTokenService authTokenService;

    private final AtomicLong nanos = new AtomicLong();
    private final UUID sessionId = UUID.randomUUID();
    private ActiveSessionChecker checker;

    @BeforeEach
    void setUp() {
        checker = new ActiveSessionChecker(authTokenService, nanos::get);
    }

    private Mono<Boolean> isActive(String tenant, UUID session) {
        return checker.isActive(session).contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, tenant));
    }

    private void advance(Duration time) {
        nanos.addAndGet(time.toNanos());
    }

    @Test
    void isActive_firstCall_asksTheServiceAndEmitsItsAnswer() {
        // Arrange
        when(authTokenService.isSessionActive(sessionId)).thenReturn(Mono.just(true));

        // Act & Assert
        StepVerifier.create(isActive(TENANT, sessionId)).expectNext(true).verifyComplete();
        verify(authTokenService, times(1)).isSessionActive(sessionId);
    }

    @Test
    void isActive_defaultConstructor_usesTheSystemClockAndCachesTheAnswer() {
        // Arrange
        var withSystemClock = new ActiveSessionChecker(authTokenService);
        when(authTokenService.isSessionActive(sessionId)).thenReturn(Mono.just(true));
        var call = withSystemClock.isActive(sessionId)
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT));

        // Act & Assert
        StepVerifier.create(call).expectNext(true).verifyComplete();
        StepVerifier.create(call).expectNext(true).verifyComplete();
        verify(authTokenService, times(1)).isSessionActive(sessionId);
    }

    @Test
    void isActive_withinTheTtl_servesTheCachedAnswerWithoutAskingAgain() {
        // Arrange
        when(authTokenService.isSessionActive(sessionId)).thenReturn(Mono.just(true));
        isActive(TENANT, sessionId).block();

        // Act
        advance(ActiveSessionChecker.CACHE_TTL.minusSeconds(1));

        // Assert
        StepVerifier.create(isActive(TENANT, sessionId)).expectNext(true).verifyComplete();
        verify(authTokenService, times(1)).isSessionActive(sessionId);
    }

    @Test
    void isActive_afterTheTtl_asksTheServiceAgain() {
        // Arrange: the session ends after the first answer
        when(authTokenService.isSessionActive(sessionId)).thenReturn(Mono.just(true), Mono.just(false));
        isActive(TENANT, sessionId).block();

        // Act
        advance(ActiveSessionChecker.CACHE_TTL.plusSeconds(1));

        // Assert
        StepVerifier.create(isActive(TENANT, sessionId)).expectNext(false).verifyComplete();
        verify(authTokenService, times(2)).isSessionActive(sessionId);
    }

    @Test
    void isActive_endedSession_isCachedForTheTtlToo() {
        // Arrange
        when(authTokenService.isSessionActive(sessionId)).thenReturn(Mono.just(false));
        isActive(TENANT, sessionId).block();

        // Act & Assert
        StepVerifier.create(isActive(TENANT, sessionId)).expectNext(false).verifyComplete();
        verify(authTokenService, times(1)).isSessionActive(sessionId);
    }

    @Test
    void isActive_serviceFails_propagatesTheErrorAndCachesNothing() {
        // Arrange: a transient failure first, then a definitive answer
        when(authTokenService.isSessionActive(sessionId))
                .thenReturn(Mono.error(new IllegalStateException("database down")), Mono.just(true));

        // Act & Assert
        StepVerifier.create(isActive(TENANT, sessionId)).expectError(IllegalStateException.class).verify();
        StepVerifier.create(isActive(TENANT, sessionId)).expectNext(true).verifyComplete();
        verify(authTokenService, times(2)).isSessionActive(sessionId);
    }

    @Test
    void isActive_serviceEmitsNothing_isNotActiveButIsNotRemembered() {
        // Arrange
        when(authTokenService.isSessionActive(sessionId)).thenReturn(Mono.empty(), Mono.just(true));

        // Act & Assert
        StepVerifier.create(isActive(TENANT, sessionId)).expectNext(false).verifyComplete();
        StepVerifier.create(isActive(TENANT, sessionId)).expectNext(true).verifyComplete();
        verify(authTokenService, times(2)).isSessionActive(sessionId);
    }

    @Test
    void isActive_sameSessionIdInAnotherTenant_doesNotShareTheCachedAnswer() {
        // Arrange
        when(authTokenService.isSessionActive(sessionId)).thenReturn(Mono.just(true), Mono.just(false));
        isActive(TENANT, sessionId).block();

        // Act & Assert
        StepVerifier.create(isActive("cgcom", sessionId)).expectNext(false).verifyComplete();
        verify(authTokenService, times(2)).isSessionActive(sessionId);
    }

    @Test
    void forget_cachedSession_dropsItSoTheNextCallAsksTheServiceAgain() {
        // Arrange: this instance has just ended the session
        when(authTokenService.isSessionActive(sessionId)).thenReturn(Mono.just(true), Mono.just(false));
        isActive(TENANT, sessionId).block();

        // Act
        checker.forget(sessionId).contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT)).block();

        // Assert
        StepVerifier.create(isActive(TENANT, sessionId)).expectNext(false).verifyComplete();
        verify(authTokenService, times(2)).isSessionActive(sessionId);
    }

    @Test
    void forget_sessionNeverCached_doesNothing() {
        // Act & Assert
        StepVerifier.create(checker.forget(sessionId)
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT))).verifyComplete();
        verify(authTokenService, never()).isSessionActive(sessionId);
    }
}
