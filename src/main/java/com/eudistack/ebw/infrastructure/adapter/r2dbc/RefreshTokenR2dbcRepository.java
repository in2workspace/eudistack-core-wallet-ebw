package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.RefreshTokenMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringRefreshTokenRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public class RefreshTokenR2dbcRepository implements RefreshTokenRepository {

    private final SpringRefreshTokenRepository springRepository;

    public RefreshTokenR2dbcRepository(SpringRefreshTokenRepository springRepository) {
        this.springRepository = springRepository;
    }

    @Override
    public Mono<RefreshToken> findByTokenHash(String tokenHash) {
        return springRepository.findByTokenHash(tokenHash).map(RefreshTokenMapper::toDomain);
    }

    @Override
    public Mono<RefreshToken> insert(RefreshToken token) {
        var entity = RefreshTokenMapper.toEntity(token);
        entity.markNew();
        return springRepository.save(entity).map(RefreshTokenMapper::toDomain);
    }

    @Override
    public Mono<Boolean> revokeIfActive(UUID id) {
        return springRepository.revokeIfActive(id).map(rows -> rows > 0).defaultIfEmpty(false);
    }

    @Override
    public Mono<Boolean> hasActiveToken(UUID sessionId) {
        return springRepository.hasActiveToken(sessionId).defaultIfEmpty(false);
    }

    @Override
    public Mono<Void> revokeBySessionId(UUID sessionId) {
        return springRepository.revokeBySessionId(sessionId).then();
    }

    @Override
    public Mono<Long> revokeByUserIdExceptSession(UUID userId, UUID keptSessionId) {
        return springRepository.revokeByUserIdExceptSession(userId, keptSessionId).defaultIfEmpty(0L);
    }

    @Override
    public Mono<Void> revokeByPasskeyId(UUID passkeyId) {
        return springRepository.revokeByPasskeyId(passkeyId);
    }

    @Override
    public Mono<Long> countActiveByPasskeyId(UUID passkeyId) {
        return springRepository.countActiveByPasskeyId(passkeyId);
    }

    @Override
    public Mono<Long> deleteSessionsEndedBefore(java.time.Instant cutoff) {
        return springRepository.deleteSessionsEndedBefore(cutoff).defaultIfEmpty(0L);
    }
}
