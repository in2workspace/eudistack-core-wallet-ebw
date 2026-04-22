package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.PasskeyMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringUserPasskeyRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public class UserPasskeyR2dbcRepository implements UserPasskeyRepository {

    private final SpringUserPasskeyRepository springRepository;

    public UserPasskeyR2dbcRepository(SpringUserPasskeyRepository springRepository) {
        this.springRepository = springRepository;
    }

    @Override
    public Flux<UserPasskey> findByUserId(UUID userId) {
        return springRepository.findByUserId(userId).map(PasskeyMapper::toDomain);
    }

    @Override
    public Mono<UserPasskey> findByIdAndUserId(UUID id, UUID userId) {
        return springRepository.findByIdAndUserId(id, userId).map(PasskeyMapper::toDomain);
    }

    @Override
    public Mono<UserPasskey> findByUserIdAndCredentialId(UUID userId, String credentialId) {
        return springRepository.findByUserIdAndCredentialId(userId, credentialId).map(PasskeyMapper::toDomain);
    }

    @Override
    public Mono<UserPasskey> save(UserPasskey passkey) {
        return springRepository.existsById(passkey.getId())
                .flatMap(exists -> {
                    var entity = PasskeyMapper.toEntity(passkey);
                    if (!exists) entity.markNew();
                    return springRepository.save(entity);
                })
                .map(PasskeyMapper::toDomain);
    }

    @Override
    public Mono<Void> deleteById(UUID id) {
        return springRepository.deleteById(id);
    }

    @Override
    public Mono<Long> countByUserId(UUID userId) {
        return springRepository.countByUserId(userId);
    }
}
