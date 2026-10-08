package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.WalletUserEntity;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.UserMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringWalletUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link WalletUserR2dbcRepository} — lookups and insert-vs-update dispatch.
 */
class WalletUserR2dbcRepositoryTest {

    private SpringWalletUserRepository springRepository;
    private WalletUserR2dbcRepository repository;

    @BeforeEach
    void setUp() {
        springRepository = mock(SpringWalletUserRepository.class);
        repository = new WalletUserR2dbcRepository(springRepository);
    }

    @Test
    void findByIdAndFindByEmail_existingUser_mapItToTheDomain() {
        // Arrange
        var user = WalletUser.create("holder@example.com");
        var entity = UserMapper.toEntity(user);
        when(springRepository.findById(user.getId())).thenReturn(Mono.just(entity));
        when(springRepository.findByEmail("holder@example.com")).thenReturn(Mono.just(entity));

        // Act
        var byId = repository.findById(user.getId());
        var byEmail = repository.findByEmail("holder@example.com");

        // Assert
        StepVerifier.create(byId).assertNext(u -> assertThat(u).usingRecursiveComparison().isEqualTo(user))
                .verifyComplete();
        StepVerifier.create(byEmail).assertNext(u -> assertThat(u.getId()).isEqualTo(user.getId())).verifyComplete();
    }

    @Test
    void save_newUser_insertsAnEntityMarkedNew() {
        // Arrange
        var user = WalletUser.create("holder@example.com");
        when(springRepository.existsById(user.getId())).thenReturn(Mono.just(false));
        when(springRepository.save(any(WalletUserEntity.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = repository.save(user);

        // Assert
        StepVerifier.create(result).expectNextCount(1).verifyComplete();
        var saved = ArgumentCaptor.forClass(WalletUserEntity.class);
        verify(springRepository).save(saved.capture());
        assertThat(saved.getValue().isNew()).isTrue();
        assertThat(saved.getValue().getEmail()).isEqualTo("holder@example.com");
    }

    @Test
    void save_existingUser_updatesWithoutMarkingNew() {
        // Arrange
        var user = WalletUser.create("holder@example.com");
        when(springRepository.existsById(user.getId())).thenReturn(Mono.just(true));
        when(springRepository.save(any(WalletUserEntity.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = repository.save(user);

        // Assert
        StepVerifier.create(result).expectNextCount(1).verifyComplete();
        var saved = ArgumentCaptor.forClass(WalletUserEntity.class);
        verify(springRepository).save(saved.capture());
        assertThat(saved.getValue().isNew()).isFalse();
    }
}
