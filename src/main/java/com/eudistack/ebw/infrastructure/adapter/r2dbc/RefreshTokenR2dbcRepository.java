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
    public Mono<RefreshToken> save(RefreshToken token) {
        return springRepository.existsById(token.getId())
                .flatMap(exists -> {
                    var entity = RefreshTokenMapper.toEntity(token);
                    if (!exists) entity.markNew();
                    return springRepository.save(entity);
                })
                .map(RefreshTokenMapper::toDomain);
    }

    @Override
    public Mono<Void> revokeByPasskeyId(UUID passkeyId) {
        return springRepository.revokeByPasskeyId(passkeyId);
    }

    @Override
    public Mono<Void> revokeByUserId(UUID userId) {
        return springRepository.revokeByUserId(userId);
    }

    @Override
    public Mono<Long> countActiveByPasskeyId(UUID passkeyId) {
        return springRepository.countActiveByPasskeyId(passkeyId);
    }
}
