package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.RegistrationTicket;
import com.eudistack.ebw.domain.model.exception.InvalidTicketException;
import com.eudistack.ebw.domain.repository.RegistrationTicketRepository;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Unit tests for {@link RegistrationTicketService}. */
@ExtendWith(MockitoExtension.class)
class RegistrationTicketServiceTest {

    private static final String RAW_TICKET = "raw-ticket";

    @Mock
    private RegistrationTicketRepository ticketRepository;
    @Mock
    private HashProvider hashProvider;
    @Mock
    private SecureRandomGenerator randomGenerator;

    private RegistrationTicketService service;

    @BeforeEach
    void setUp() {
        service = new RegistrationTicketService(ticketRepository, hashProvider, randomGenerator);
    }

    private RegistrationTicket ticket() {
        var now = Instant.now();
        return new RegistrationTicket(UUID.randomUUID(), UUID.randomUUID(), "hash", now.plusSeconds(300), null, now);
    }

    @Test
    void issue_account_storesOnlyTheHashAndEmitsTheRawTicket() {
        // Arrange
        var userId = UUID.randomUUID();
        var bytes = new byte[32];
        Arrays.fill(bytes, (byte) 7);
        var raw = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        when(randomGenerator.generateBytes(32)).thenReturn(bytes);
        when(hashProvider.sha256(raw)).thenReturn("stored-hash");
        when(ticketRepository.insert(any())).thenAnswer(call -> Mono.just(call.getArgument(0)));

        // Act & Assert
        StepVerifier.create(service.issue(userId)).expectNext(raw).verifyComplete();
        var stored = ArgumentCaptor.forClass(RegistrationTicket.class);
        verify(ticketRepository).insert(stored.capture());
        assertThat(stored.getValue().userId()).isEqualTo(userId);
        assertThat(stored.getValue().tokenHash()).isEqualTo("stored-hash").doesNotContain(raw);
        assertThat(stored.getValue().consumedAt()).isNull();
    }

    @Test
    void issue_account_isValidForFiveMinutes() {
        // Arrange
        when(randomGenerator.generateBytes(32)).thenReturn(new byte[32]);
        when(hashProvider.sha256(any())).thenReturn("hash");
        when(ticketRepository.insert(any())).thenAnswer(call -> Mono.just(call.getArgument(0)));

        // Act
        service.issue(UUID.randomUUID()).block();

        // Assert
        var stored = ArgumentCaptor.forClass(RegistrationTicket.class);
        verify(ticketRepository).insert(stored.capture());
        assertThat(stored.getValue().expiresAt()).isEqualTo(stored.getValue().createdAt().plus(RegistrationTicket.TTL));
        assertThat(RegistrationTicket.TTL.toMinutes()).isEqualTo(5);
    }

    @Test
    void resolve_usableTicket_emitsItLookedUpByHash() {
        // Arrange
        var usable = ticket();
        when(hashProvider.sha256(RAW_TICKET)).thenReturn("hash");
        when(ticketRepository.findUsableByTokenHash("hash")).thenReturn(Mono.just(usable));

        // Act & Assert
        StepVerifier.create(service.resolve(RAW_TICKET)).expectNext(usable).verifyComplete();
    }

    @Test
    void resolve_unknownConsumedOrExpiredTicket_failsWithInvalidTicket() {
        // Arrange: the repository only finds usable tickets, so all three cases are empty
        when(hashProvider.sha256(RAW_TICKET)).thenReturn("hash");
        when(ticketRepository.findUsableByTokenHash("hash")).thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(service.resolve(RAW_TICKET)).expectError(InvalidTicketException.class).verify();
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", " ", "   "})
    void resolve_missingOrBlankTicket_failsWithInvalidTicketWithoutQueryingTheRepository(String raw) {
        // Act & Assert
        StepVerifier.create(service.resolve(raw)).expectError(InvalidTicketException.class).verify();
        verifyNoInteractions(ticketRepository, hashProvider);
    }

    @Test
    void consume_usableTicket_completesAndConsumesItById() {
        // Arrange
        var usable = ticket();
        when(ticketRepository.consume(usable.id())).thenReturn(Mono.just(true));

        // Act & Assert
        StepVerifier.create(service.consume(usable)).verifyComplete();
        verify(ticketRepository).consume(usable.id());
    }

    @Test
    void consume_ticketAlreadyConsumedByAnotherRequest_failsWithInvalidTicket() {
        // Arrange: the conditional update touched no row, so another request got there first
        var usable = ticket();
        when(ticketRepository.consume(usable.id())).thenReturn(Mono.just(false));

        // Act & Assert
        StepVerifier.create(service.consume(usable)).expectError(InvalidTicketException.class).verify();
    }
}
