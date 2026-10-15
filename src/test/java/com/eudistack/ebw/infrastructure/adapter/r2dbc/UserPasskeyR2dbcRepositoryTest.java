package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.VerifiedPasskeyAssertion;
import com.eudistack.ebw.domain.model.exception.RegistrationFailedException;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.UserPasskeyEntity;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.PasskeyMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringUserPasskeyRepository;
import com.eudistack.ebw.support.TestPasskeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.DataIntegrityViolationException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link UserPasskeyR2dbcRepository}: insert, mapping and the counter-guarded update. */
class UserPasskeyR2dbcRepositoryTest {

    private static final UUID USER_ID = UUID.randomUUID();

    private SpringUserPasskeyRepository springRepository;
    private UserPasskeyR2dbcRepository repository;

    @BeforeEach
    void setUp() {
        springRepository = mock(SpringUserPasskeyRepository.class);
        repository = new UserPasskeyR2dbcRepository(springRepository);
    }

    @Test
    void insert_newPasskey_savesAnEntityMarkedNewWithTheCredentialRecord() {
        // Arrange
        var passkey = TestPasskeys.create(USER_ID, "cred-1", "Laptop", "ua");
        when(springRepository.save(any(UserPasskeyEntity.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = repository.insert(passkey);

        // Assert
        StepVerifier.create(result)
                .assertNext(saved -> assertThat(saved).usingRecursiveComparison().isEqualTo(passkey))
                .verifyComplete();
        var saved = ArgumentCaptor.forClass(UserPasskeyEntity.class);
        verify(springRepository).save(saved.capture());
        assertThat(saved.getValue().isNew()).isTrue();
        assertThat(saved.getValue().getTransports()).isEqualTo("[\"internal\"]");
    }

    @Test
    void insert_duplicateCredentialId_failsWithRegistrationFailed() {
        // Arrange
        var passkey = TestPasskeys.create(USER_ID, "cred-1", "Laptop", "ua");
        when(springRepository.save(any(UserPasskeyEntity.class)))
                .thenReturn(Mono.error(new DataIntegrityViolationException("duplicate")));

        // Act + Assert
        StepVerifier.create(repository.insert(passkey)).expectError(RegistrationFailedException.class).verify();
    }

    @Test
    void finders_existingRows_mapThemToTheDomain() {
        // Arrange
        var passkey = TestPasskeys.create(USER_ID, "cred-1", "Laptop", "ua");
        var entity = PasskeyMapper.toEntity(passkey);
        when(springRepository.findByUserId(USER_ID)).thenReturn(Flux.just(entity));
        when(springRepository.findByCredentialId("cred-1")).thenReturn(Mono.just(entity));

        // Act + Assert
        StepVerifier.create(repository.findByUserId(USER_ID))
                .assertNext(found -> assertThat(found.getTransports()).containsExactly("internal"))
                .verifyComplete();
        StepVerifier.create(repository.findByCredentialId("cred-1"))
                .assertNext(found -> assertThat(found.getId()).isEqualTo(passkey.getId()))
                .verifyComplete();
    }

    @Test
    void recordAuthentication_counterAboveZero_usesTheCounterGuardedUpdate() {
        // Arrange
        var id = UUID.randomUUID();
        when(springRepository.recordCountedAuthentication(id, 5L, true, true)).thenReturn(Mono.just(1L));

        // Act + Assert
        StepVerifier.create(repository.recordAuthentication(id, new VerifiedPasskeyAssertion(5, true, true)))
                .expectNext(true).verifyComplete();
        verify(springRepository, never()).recordUncountedAuthentication(any(), anyBoolean(), anyBoolean());
    }

    @Test
    void recordAuthentication_counterRaceLost_emitsFalse() {
        // Arrange
        var id = UUID.randomUUID();
        when(springRepository.recordCountedAuthentication(id, 5L, true, true)).thenReturn(Mono.just(0L));

        // Act + Assert
        StepVerifier.create(repository.recordAuthentication(id, new VerifiedPasskeyAssertion(5, true, true)))
                .expectNext(false).verifyComplete();
    }

    @Test
    void recordAuthentication_counterZero_usesTheUncountedUpdate() {
        // Arrange
        var id = UUID.randomUUID();
        when(springRepository.recordUncountedAuthentication(id, false, true)).thenReturn(Mono.just(1L));

        // Act + Assert
        StepVerifier.create(repository.recordAuthentication(id, new VerifiedPasskeyAssertion(0, true, false)))
                .expectNext(true).verifyComplete();
        verify(springRepository, never()).recordCountedAuthentication(any(), anyLong(), anyBoolean(), anyBoolean());
    }

    @Test
    void deleteByIdAndCountByUserId_delegateToSpringData() {
        // Arrange
        var id = UUID.randomUUID();
        when(springRepository.deleteById(id)).thenReturn(Mono.empty());
        when(springRepository.countByUserId(USER_ID)).thenReturn(Mono.just(2L));

        // Act + Assert
        StepVerifier.create(repository.deleteById(id)).verifyComplete();
        StepVerifier.create(repository.countByUserId(USER_ID)).expectNext(2L).verifyComplete();
        verify(springRepository).deleteById(id);
    }
}
