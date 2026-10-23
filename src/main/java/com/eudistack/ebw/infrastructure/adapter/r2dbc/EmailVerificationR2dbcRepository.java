package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.EmailVerification;
import com.eudistack.ebw.domain.repository.EmailVerificationRepository;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.VerificationMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringEmailVerificationRepository;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

@Repository
public class EmailVerificationR2dbcRepository implements EmailVerificationRepository {

    private static final String FIND_REPLACED_SQL = """
            SELECT id, user_email, code_hash, attempts, expires_at, used, created_at FROM email_verification
             WHERE user_email = :email AND replaced_at IS NOT NULL AND created_at >= :since
             ORDER BY created_at DESC LIMIT 5
            """;

    private static final String MARK_USED_SQL = """
            UPDATE email_verification SET used = true
             WHERE id = :id AND used = false AND attempts < :maxAttempts
            """;

    private static final String INCREMENT_ATTEMPTS_SQL = """
            UPDATE email_verification SET attempts = attempts + 1 WHERE id = :id RETURNING attempts
            """;

    private final SpringEmailVerificationRepository springRepository;
    private final DatabaseClient databaseClient;

    public EmailVerificationR2dbcRepository(SpringEmailVerificationRepository springRepository,
                                            DatabaseClient databaseClient) {
        this.springRepository = springRepository;
        this.databaseClient = databaseClient;
    }

    @Override
    public Mono<EmailVerification> findLatestUnusedByEmail(String email) {
        return springRepository.findFirstByUserEmailAndUsedFalseOrderByCreatedAtDesc(email).map(VerificationMapper::toDomain);
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

    @Override
    public Flux<EmailVerification> findReplacedSince(String email, Instant since) {
        return databaseClient.sql(FIND_REPLACED_SQL)
                .bind("email", email)
                .bind("since", since)
                .map((row, metadata) -> new EmailVerification(
                        row.get("id", UUID.class), row.get("user_email", String.class),
                        row.get("code_hash", String.class), row.get("attempts", Integer.class),
                        row.get("expires_at", Instant.class), Boolean.TRUE.equals(row.get("used", Boolean.class)),
                        row.get("created_at", Instant.class)))
                .all();
    }

    @Override
    public Mono<Boolean> markUsedIfUsable(UUID id, int maxAttempts) {
        return databaseClient.sql(MARK_USED_SQL)
                .bind("id", id)
                .bind("maxAttempts", maxAttempts)
                .fetch().rowsUpdated()
                .map(rows -> rows > 0);
    }

    @Override
    public Mono<Integer> incrementAttempts(UUID id) {
        return databaseClient.sql(INCREMENT_ATTEMPTS_SQL)
                .bind("id", id)
                .map((row, metadata) -> row.get("attempts", Integer.class))
                .one();
    }
}
