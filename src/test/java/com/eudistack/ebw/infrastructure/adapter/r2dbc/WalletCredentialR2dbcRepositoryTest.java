package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.CredentialFormat;
import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.WalletCredentialEntity;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.CredentialMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringWalletCredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link WalletCredentialR2dbcRepository} — explicit insert/update dispatch via
 * {@code Persistable#isNew()} and filter normalisation. The SQL itself is covered by
 * {@code CredentialRepositoryInsertUpdateIntegrationTest}.
 */
class WalletCredentialR2dbcRepositoryTest {

    private static final UUID USER_ID = UUID.randomUUID();

    private SpringWalletCredentialRepository springRepository;
    private WalletCredentialR2dbcRepository repository;

    @BeforeEach
    void setUp() {
        springRepository = mock(SpringWalletCredentialRepository.class);
        repository = new WalletCredentialR2dbcRepository(springRepository);
    }

    @Test
    void insert_newCredential_savesAnEntityMarkedNew() {
        // Arrange
        var credential = credential();
        when(springRepository.save(any(WalletCredentialEntity.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = repository.insert(credential);

        // Assert
        StepVerifier.create(result)
                .assertNext(saved -> assertThat(saved.getId()).isEqualTo(credential.getId()))
                .verifyComplete();
        var saved = ArgumentCaptor.forClass(WalletCredentialEntity.class);
        verify(springRepository).save(saved.capture());
        assertThat(saved.getValue().isNew()).isTrue();
    }

    @Test
    void update_existingCredential_savesAnEntityNotMarkedNew() {
        // Arrange
        var credential = credential();
        when(springRepository.save(any(WalletCredentialEntity.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = repository.update(credential);

        // Assert
        StepVerifier.create(result).expectNextCount(1).verifyComplete();
        var saved = ArgumentCaptor.forClass(WalletCredentialEntity.class);
        verify(springRepository).save(saved.capture());
        assertThat(saved.getValue().isNew()).isFalse();
    }

    @Test
    void findByIdAndUserId_existingRow_mapsItToTheDomain() {
        // Arrange
        var credential = credential();
        when(springRepository.findByIdAndUserId(credential.getId(), USER_ID))
                .thenReturn(Mono.just(CredentialMapper.toEntity(credential)));

        // Act
        var result = repository.findByIdAndUserId(credential.getId(), USER_ID);

        // Assert
        StepVerifier.create(result)
                .assertNext(found -> assertThat(found.getCredentialType()).isEqualTo("Type"))
                .verifyComplete();
    }

    @Test
    void findAllByUserId_rows_areMapped() {
        // Arrange
        when(springRepository.findAllByUserId(USER_ID))
                .thenReturn(Flux.just(CredentialMapper.toEntity(credential()), CredentialMapper.toEntity(credential())));

        // Act
        var result = repository.findAllByUserId(USER_ID);

        // Assert
        StepVerifier.create(result).expectNextCount(2).verifyComplete();
    }

    @Test
    void findAllByUserIdAndFilters_statusAndValues_passesStatusNameAndValues() {
        // Arrange
        when(springRepository.findAllByUserIdAndFilters(USER_ID, "REVOKED", "cfg-1", "https://issuer"))
                .thenReturn(Flux.empty());

        // Act
        var result = repository.findAllByUserIdAndFilters(USER_ID, CredentialStatus.REVOKED, "cfg-1", "https://issuer");

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(springRepository).findAllByUserIdAndFilters(USER_ID, "REVOKED", "cfg-1", "https://issuer");
    }

    @Test
    void findAllByUserIdAndFilters_nullStatusAndBlankValues_passesNulls() {
        // Arrange
        when(springRepository.findAllByUserIdAndFilters(USER_ID, null, null, null)).thenReturn(Flux.empty());

        // Act
        var result = repository.findAllByUserIdAndFilters(USER_ID, null, " ", "");

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(springRepository).findAllByUserIdAndFilters(USER_ID, null, null, null);
    }

    @Test
    void deleteById_delegatesToSpringData() {
        // Arrange
        var id = UUID.randomUUID();
        when(springRepository.deleteById(id)).thenReturn(Mono.empty());

        // Act
        var result = repository.deleteById(id);

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(springRepository).deleteById(id);
    }

    private static WalletCredential credential() {
        var now = Instant.now();
        return new WalletCredential(UUID.randomUUID(), USER_ID, "raw", CredentialFormat.DC_SD_JWT, "cfg-1", "kid",
                "Type", "vct", "https://issuer", "sub", now, null, CredentialStatus.VALID, Map.of(), "hk", now, now);
    }
}
