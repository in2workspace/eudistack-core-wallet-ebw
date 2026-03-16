package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.EmailVerification;
import com.eudistack.ebw.domain.repository.EmailVerificationRepository;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.VerificationMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringEmailVerificationRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public class EmailVerificationR2dbcRepository implements EmailVerificationRepository {

    private final SpringEmailVerificationRepository springRepository;

    public EmailVerificationR2dbcRepository(SpringEmailVerificationRepository springRepository) {
        this.springRepository = springRepository;
    }

    @Override
    public Mono<EmailVerification> findActiveByEmail(String email) {
        return springRepository.findActiveByEmail(email).map(VerificationMapper::toDomain);
    }

    @Override
    public Mono<EmailVerification> save(EmailVerification verification) {
        return springRepository.existsById(verification.getId())
                .flatMap(exists -> {
                    var entity = VerificationMapper.toEntity(verification);
                    if (!exists) entity.markNew();
                    return springRepository.save(entity);
                })
                .map(VerificationMapper::toDomain);
    }

    @Override
    public Mono<Void> invalidateByEmail(String email) {
        return springRepository.invalidateByEmail(email);
    }
}
