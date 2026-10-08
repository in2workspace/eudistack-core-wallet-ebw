package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.UserPasskeyEntity;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.PasskeyMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringUserPasskeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link UserPasskeyR2dbcRepository} — insert-vs-update decided by an existence check, and
 * entity ↔ domain mapping through {@link PasskeyMapper}.
 */
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
    void save_unknownId_insertsAnEntityMarkedNew() {
        // Arrange
        var passkey = UserPasskey.create(USER_ID, "cred-1", "Laptop", "ua");
        when(springRepository.existsById(passkey.getId())).thenReturn(Mono.just(false));
        when(springRepository.save(any(UserPasskeyEntity.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = repository.save(passkey);

        // Assert
        StepVerifier.create(result)
                .assertNext(saved -> assertThat(saved).usingRecursiveComparison().isEqualTo(passkey))
                .verifyComplete();
        var saved = ArgumentCaptor.forClass(UserPasskeyEntity.class);
        verify(springRepository).save(saved.capture());
        assertThat(saved.getValue().isNew()).isTrue();
    }

    @Test
    void save_existingId_updatesWithoutMarkingNew() {
        // Arrange
        var passkey = UserPasskey.create(USER_ID, "cred-1", "Laptop", "ua");
        when(springRepository.existsById(passkey.getId())).thenReturn(Mono.just(true));
        when(springRepository.save(any(UserPasskeyEntity.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = repository.save(passkey);

        // Assert
        StepVerifier.create(result).expectNextCount(1).verifyComplete();
        var saved = ArgumentCaptor.forClass(UserPasskeyEntity.class);
        verify(springRepository).save(saved.capture());
        assertThat(saved.getValue().isNew()).isFalse();
    }

    @Test
    void finders_existingRows_mapThemToTheDomain() {
        // Arrange
        var passkey = UserPasskey.create(USER_ID, "cred-1", "Laptop", "ua");
        var entity = PasskeyMapper.toEntity(passkey);
        when(springRepository.findByUserId(USER_ID)).thenReturn(Flux.just(entity));
        when(springRepository.findByIdAndUserId(passkey.getId(), USER_ID)).thenReturn(Mono.just(entity));
        when(springRepository.findByUserIdAndCredentialId(USER_ID, "cred-1")).thenReturn(Mono.just(entity));

        // Act
        var byUser = repository.findByUserId(USER_ID);
        var byId = repository.findByIdAndUserId(passkey.getId(), USER_ID);
        var byCredential = repository.findByUserIdAndCredentialId(USER_ID, "cred-1");

        // Assert
        StepVerifier.create(byUser).assertNext(p -> assertThat(p.getDisplayName()).isEqualTo("Laptop")).verifyComplete();
        StepVerifier.create(byId).assertNext(p -> assertThat(p.getId()).isEqualTo(passkey.getId())).verifyComplete();
        StepVerifier.create(byCredential)
                .assertNext(p -> assertThat(p.getCredentialId()).isEqualTo("cred-1"))
                .verifyComplete();
    }

    @Test
    void deleteByIdAndCountByUserId_delegateToSpringData() {
        // Arrange
        var id = UUID.randomUUID();
        when(springRepository.deleteById(id)).thenReturn(Mono.empty());
        when(springRepository.countByUserId(USER_ID)).thenReturn(Mono.just(2L));

        // Act
        var delete = repository.deleteById(id);
        var count = repository.countByUserId(USER_ID);

        // Assert
        StepVerifier.create(delete).verifyComplete();
        StepVerifier.create(count).expectNext(2L).verifyComplete();
        verify(springRepository).deleteById(id);
    }
}
