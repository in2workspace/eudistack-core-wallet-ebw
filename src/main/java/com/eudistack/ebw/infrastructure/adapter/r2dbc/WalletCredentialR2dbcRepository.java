package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.WalletCredentialEntity;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.CredentialMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringWalletCredentialRepository;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.relational.core.query.Criteria;
import org.springframework.data.relational.core.query.Query;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.UUID;

@Repository
public class WalletCredentialR2dbcRepository implements WalletCredentialRepository {

    private final SpringWalletCredentialRepository springRepository;
    private final R2dbcEntityTemplate template;

    public WalletCredentialR2dbcRepository(SpringWalletCredentialRepository springRepository,
                                            R2dbcEntityTemplate template) {
        this.springRepository = springRepository;
        this.template = template;
    }

    @Override
    public Mono<WalletCredential> save(WalletCredential credential) {
        return springRepository.existsById(credential.getId())
                .flatMap(exists -> {
                    var entity = CredentialMapper.toEntity(credential);
                    if (!exists) entity.markNew();
                    return springRepository.save(entity);
                })
                .map(CredentialMapper::toDomain);
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
        var criteria = new ArrayList<Criteria>();
        criteria.add(Criteria.where("user_id").is(userId));

        if (status != null) {
            criteria.add(Criteria.where("status").is(status.name()));
        }
        if (credentialConfigId != null && !credentialConfigId.isBlank()) {
            criteria.add(Criteria.where("credential_config_id").is(credentialConfigId));
        }
        if (issuer != null && !issuer.isBlank()) {
            criteria.add(Criteria.where("issuer").is(issuer));
        }

        var combined = Criteria.from(criteria);
        return template.select(WalletCredentialEntity.class)
                .matching(Query.query(combined))
                .all()
                .map(CredentialMapper::toDomain);
    }

    @Override
    public Mono<Void> deleteById(UUID id) {
        return springRepository.deleteById(id);
    }
}
