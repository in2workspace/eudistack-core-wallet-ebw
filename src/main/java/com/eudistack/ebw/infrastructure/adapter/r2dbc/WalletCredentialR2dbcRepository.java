package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.CredentialMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringWalletCredentialRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * R2DBC adapter for {@link WalletCredentialRepository}.
 *
 * <p>Uses explicit {@code insert} / {@code update} ports instead of a single {@code save}
 * (Option B per EUDI-040 review W4) because the application workflows unambiguously know
 * whether they are creating a new credential ({@code StoreCredentialWorkflow}) or mutating
 * an existing one ({@code UpdateCredentialStatusWorkflow}). This avoids the
 * {@code SELECT EXISTS} round-trip previously required to drive
 * {@link org.springframework.data.domain.Persistable#isNew()} on every save.
 */
@Repository
public class WalletCredentialR2dbcRepository implements WalletCredentialRepository {

    private final SpringWalletCredentialRepository springRepository;

    public WalletCredentialR2dbcRepository(SpringWalletCredentialRepository springRepository) {
        this.springRepository = springRepository;
    }

    @Override
    public Mono<WalletCredential> insert(WalletCredential credential) {
        var entity = CredentialMapper.toEntity(credential);
        entity.markNew();
        return springRepository.save(entity).map(CredentialMapper::toDomain);
    }

    @Override
    public Mono<WalletCredential> update(WalletCredential credential) {
        var entity = CredentialMapper.toEntity(credential);
        // isNew defaults to false → Spring Data R2DBC dispatches UPDATE.
        return springRepository.save(entity).map(CredentialMapper::toDomain);
    }

    @Override
    public Mono<WalletCredential> findByIdAndUserId(UUID id, UUID userId) {
        return springRepository.findByIdAndUserId(id, userId)
                .map(CredentialMapper::toDomain);
    }

    @Override
    public Flux<WalletCredential> findAllByUserId(UUID userId) {
        return springRepository.findAllByUserIdWithoutRaw(userId)
                .map(CredentialMapper::toDomain);
    }

    @Override
    public Flux<WalletCredential> findAllByUserIdAndFilters(UUID userId, CredentialStatus status,
                                                             String credentialConfigId, String issuer) {
        // Native @Query with (:param IS NULL OR column = :param) predicates keeps the projection
        // consistent with findAllByUserIdWithoutRaw: credential_raw is NOT selected because list
        // endpoints never return it (EUDI-040 review W2).
        var statusName = status != null ? status.name() : null;
        var configId = (credentialConfigId != null && !credentialConfigId.isBlank()) ? credentialConfigId : null;
        var issuerFilter = (issuer != null && !issuer.isBlank()) ? issuer : null;
        return springRepository.findAllByUserIdAndFiltersWithoutRaw(userId, statusName, configId, issuerFilter)
                .map(CredentialMapper::toDomain);
    }

    @Override
    public Mono<Void> deleteById(UUID id) {
        return springRepository.deleteById(id);
    }
}
