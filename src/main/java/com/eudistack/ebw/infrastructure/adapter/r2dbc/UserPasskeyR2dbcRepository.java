package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.VerifiedPasskeyAssertion;
import com.eudistack.ebw.domain.model.exception.RegistrationFailedException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.PasskeyMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringUserPasskeyRepository;
import org.springframework.dao.DataIntegrityViolationException;
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
    public Mono<UserPasskey> findByCredentialId(String credentialId) {
        return springRepository.findByCredentialId(credentialId).map(PasskeyMapper::toDomain);
    }

    /** A concurrent registration of the same credential id hits the tenant-wide unique constraint. */
    @Override
    public Mono<UserPasskey> insert(UserPasskey passkey) {
        var entity = PasskeyMapper.toEntity(passkey);
        entity.markNew();
        return springRepository.save(entity)
                .map(PasskeyMapper::toDomain)
                .onErrorMap(DataIntegrityViolationException.class,
                        e -> new RegistrationFailedException("credential already registered in the tenant"));
    }

    @Override
    public Mono<UserPasskey> updateDisplayName(UserPasskey passkey) {
        return springRepository.updateDisplayName(passkey.getId(), passkey.getDisplayName())
                .then(springRepository.findById(passkey.getId()))
                .map(PasskeyMapper::toDomain);
    }

    @Override
    public Mono<Boolean> recordAuthentication(UUID id, VerifiedPasskeyAssertion assertion) {
        Mono<Long> updated = assertion.signCount() > 0
                ? springRepository.recordCountedAuthentication(id, assertion.signCount(), assertion.backupState(),
                        assertion.userVerified())
                : springRepository.recordUncountedAuthentication(id, assertion.backupState(),
                        assertion.userVerified());
        return updated.map(rows -> rows > 0).defaultIfEmpty(false);
    }

    @Override
    public Mono<Void> deleteById(UUID id) {
        return springRepository.deleteById(id);
    }

    @Override
    public Mono<Long> countByUserId(UUID userId) {
        return springRepository.countByUserId(userId);
    }

    @Override
    public Mono<Void> touchLastUsed(UUID id) {
        return springRepository.touchLastUsed(id);
    }
}
