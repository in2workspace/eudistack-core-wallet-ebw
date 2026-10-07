package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.ActivityType;
import com.eudistack.ebw.domain.model.WalletActivity;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.ActivityMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringWalletActivityRepository;
import io.r2dbc.postgresql.codec.Json;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link WalletActivityR2dbcRepository} — the idempotent insert receives every column and
 * the recent-activity query result is mapped (EUD-141).
 */
class WalletActivityR2dbcRepositoryTest {

    private SpringWalletActivityRepository springRepository;
    private WalletActivityR2dbcRepository repository;

    @BeforeEach
    void setUp() {
        springRepository = mock(SpringWalletActivityRepository.class);
        repository = new WalletActivityR2dbcRepository(springRepository);
    }

    @Test
    void insertIfAbsent_newActivity_passesEveryColumnAndMapsTheInsertedRow() {
        // Arrange
        var activity = WalletActivity.create(UUID.randomUUID(), ActivityType.PRESENTED, "LEAR", "https://verifier",
                "details", List.of("given_name"));
        when(springRepository.insertIfAbsent(any(), any(), anyString(), anyString(), anyString(), any(), any(), any()))
                .thenReturn(Mono.just(ActivityMapper.toEntity(activity)));

        // Act
        var result = repository.insertIfAbsent(activity);

        // Assert
        StepVerifier.create(result)
                .assertNext(saved -> assertThat(saved).usingRecursiveComparison().isEqualTo(activity))
                .verifyComplete();
        var sharedAttributes = ArgumentCaptor.forClass(Json.class);
        verify(springRepository).insertIfAbsent(eq(activity.getId()), eq(activity.getUserId()), eq("PRESENTED"),
                eq("LEAR"), eq("https://verifier"), eq("details"), sharedAttributes.capture(),
                eq(activity.getCreatedAt()));
        assertThat(sharedAttributes.getValue().asString()).isEqualTo("[\"given_name\"]");
    }

    @Test
    void insertIfAbsent_alreadyRecorded_completesEmpty() {
        // Arrange
        var activity = WalletActivity.create(UUID.randomUUID(), ActivityType.ISSUED, "LEAR", "issuer", null, null);
        when(springRepository.insertIfAbsent(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.empty());

        // Act
        var result = repository.insertIfAbsent(activity);

        // Assert
        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void findRecentByUserId_rows_areMappedInOrder() {
        // Arrange
        var userId = UUID.randomUUID();
        var first = WalletActivity.create(userId, ActivityType.ISSUED, "A", "issuer", null, null);
        var second = WalletActivity.create(userId, ActivityType.DELETED, "B", "wallet", null, null);
        when(springRepository.findRecentByUserId(userId, 200))
                .thenReturn(Flux.just(ActivityMapper.toEntity(first), ActivityMapper.toEntity(second)));

        // Act
        var result = repository.findRecentByUserId(userId, 200);

        // Assert
        StepVerifier.create(result.map(WalletActivity::getCredentialName))
                .expectNext("A", "B")
                .verifyComplete();
    }
}
