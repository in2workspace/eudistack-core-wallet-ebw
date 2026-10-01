package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SessionRevocationCheckerTest {

    private RefreshTokenRepository refreshTokenRepository;
    private SessionRevocationChecker checker;

    @BeforeEach
    void setUp() {
        refreshTokenRepository = mock(RefreshTokenRepository.class);
        checker = new SessionRevocationChecker(refreshTokenRepository);
    }

    @Test
    void isValid_activeSession_returnsTrue() {
        var sessionId = UUID.randomUUID();
        var token = RefreshToken.create(UUID.randomUUID(), null, "hash", Instant.now().plusSeconds(3600));
        when(refreshTokenRepository.findById(sessionId)).thenReturn(Mono.just(token));

        StepVerifier.create(checker.isValid(sessionId)).expectNext(true).verifyComplete();
    }

    @Test
    void isValid_revokedSession_returnsFalse() {
        var sessionId = UUID.randomUUID();
        var token = RefreshToken.create(UUID.randomUUID(), null, "hash", Instant.now().plusSeconds(3600));
        token.revoke();
        when(refreshTokenRepository.findById(sessionId)).thenReturn(Mono.just(token));

        StepVerifier.create(checker.isValid(sessionId)).expectNext(false).verifyComplete();
    }

    @Test
    void isValid_unknownSession_returnsFalse() {
        var sessionId = UUID.randomUUID();
        when(refreshTokenRepository.findById(sessionId)).thenReturn(Mono.empty());

        StepVerifier.create(checker.isValid(sessionId)).expectNext(false).verifyComplete();
    }

    @Test
    void isValid_calledTwiceForSameSession_hitsRepositoryOnlyOnce() {
        // The whole point of the cache: avoid a DB round trip on every authenticated
        // request. A repeated check within the cache window must be served from memory.
        var sessionId = UUID.randomUUID();
        var token = RefreshToken.create(UUID.randomUUID(), null, "hash", Instant.now().plusSeconds(3600));
        when(refreshTokenRepository.findById(sessionId)).thenReturn(Mono.just(token));

        StepVerifier.create(checker.isValid(sessionId)).expectNext(true).verifyComplete();
        StepVerifier.create(checker.isValid(sessionId)).expectNext(true).verifyComplete();

        verify(refreshTokenRepository, times(1)).findById(sessionId);
    }

    @Test
    void invalidateAll_forcesTheNextCheckBackToTheRepository() {
        // The eager side of the fix: a revocation must be visible immediately on this
        // instance, not only once the cache entry naturally expires.
        var sessionId = UUID.randomUUID();
        var token = RefreshToken.create(UUID.randomUUID(), null, "hash", Instant.now().plusSeconds(3600));
        when(refreshTokenRepository.findById(sessionId)).thenReturn(Mono.just(token));

        StepVerifier.create(checker.isValid(sessionId)).expectNext(true).verifyComplete();

        token.revoke();
        checker.invalidateAll();

        StepVerifier.create(checker.isValid(sessionId)).expectNext(false).verifyComplete();
        verify(refreshTokenRepository, times(2)).findById(sessionId);
    }
}
