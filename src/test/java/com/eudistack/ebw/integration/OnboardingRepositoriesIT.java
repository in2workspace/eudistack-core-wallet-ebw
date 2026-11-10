package com.eudistack.ebw.integration;

import com.eudistack.ebw.domain.model.ExpiredPreregistration;
import com.eudistack.ebw.domain.model.OnboardingDisavowal;
import com.eudistack.ebw.domain.model.OnboardingPreregistration;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.RegistrationTicket;
import com.eudistack.ebw.domain.repository.OnboardingDisavowalRepository;
import com.eudistack.ebw.domain.repository.OnboardingPreregistrationRepository;
import com.eudistack.ebw.domain.repository.RegistrationTicketRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;

/**
 * V10 and the onboarding repositories against PostgreSQL (EUD-315 task 2): atomic redemption,
 * hash-only storage (NFR-6), physical deletion, registration tickets of a pre-registration.
 */
class OnboardingRepositoriesIT extends IntegrationTestBase {

    @Autowired private OnboardingPreregistrationRepository preregistrationRepository;
    @Autowired private OnboardingDisavowalRepository disavowalRepository;
    @Autowired private RegistrationTicketRepository ticketRepository;

    private static <T> T block(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT)).block();
    }

    private static <T> List<T> block(Flux<T> flux) {
        return flux.contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT)).collectList().block();
    }

    private static String hash() {
        return UUID.randomUUID().toString().replace("-", "") + "00000000000000000000000000000000";
    }

    private OnboardingPreregistration insert(String tokenHash, Duration ttl) {
        return block(preregistrationRepository.insert(OnboardingPreregistration.create(tokenHash,
                "prereg-" + System.nanoTime() + "@example.com", "openid-credential-offer://?credential_offer_uri=x",
                "system-a", ttl)));
    }

    @Test
    void redeem_validTicket_isSingleUse() {
        // Arrange
        var tokenHash = hash();
        var stored = insert(tokenHash, Duration.ofMinutes(5));

        // Act
        var first = block(preregistrationRepository.redeem(tokenHash));
        var second = block(preregistrationRepository.redeem(tokenHash));

        // Assert
        assertThat(first).isNotNull();
        assertThat(first.id()).isEqualTo(stored.id());
        assertThat(first.redeemedAt()).isNotNull();
        assertThat(first.email()).isEqualTo(stored.email());
        assertThat(second).isNull();
        assertThat(query("SELECT token_hash FROM onboarding_preregistration WHERE id = '" + stored.id() + "'"))
                .singleElement().satisfies(row -> assertThat(row).containsEntry("token_hash", tokenHash));
    }

    @Test
    void redeem_expiredTicket_isEmpty() {
        // Arrange
        var tokenHash = hash();
        var stored = insert(tokenHash, Duration.ofMinutes(5));
        sql("UPDATE onboarding_preregistration SET expires_at = now() - interval '1 second' WHERE id = '"
                + stored.id() + "'");

        // Act + Assert
        assertThat(block(preregistrationRepository.redeem(tokenHash))).isNull();
    }

    @Test
    void keepUntil_extendsTheLifetimeButNeverShortensIt() {
        // Arrange: decision P8, the redemption keeps the pre-registration for its registration ticket
        var stored = insert(hash(), Duration.ofMinutes(1));
        var later = stored.expiresAt().plus(Duration.ofMinutes(4));

        // Act
        block(preregistrationRepository.keepUntil(stored.id(), later));
        block(preregistrationRepository.keepUntil(stored.id(), stored.expiresAt().minus(Duration.ofMinutes(10))));

        // Assert
        assertThat(block(preregistrationRepository.findById(stored.id())).expiresAt())
                .isCloseTo(later, within(1, ChronoUnit.MILLIS));
    }

    @Test
    void assignUserHandle_thenFind_returnsTheHandle() {
        // Arrange
        var stored = insert(hash(), Duration.ofMinutes(5));
        var handle = new byte[32];
        handle[0] = 7;

        // Act
        block(preregistrationRepository.assignUserHandle(stored.id(), handle));

        // Assert
        assertThat(block(preregistrationRepository.findById(stored.id())).webauthnUserHandle()).isEqualTo(handle);
    }

    @Test
    void deleteById_deletesTheRowAndItsRegistrationTickets() {
        // Arrange
        var stored = insert(hash(), Duration.ofMinutes(5));
        var ticket = RegistrationTicket.issueForPreregistration(null, stored.id(), hash(),
                RegistrationTicket.TTL);
        block(ticketRepository.insert(ticket));
        assertThat(block(ticketRepository.findUsableByTokenHash(ticket.tokenHash())).preregistrationId())
                .isEqualTo(stored.id());

        // Act
        var deleted = block(preregistrationRepository.deleteById(stored.id()));

        // Assert
        assertThat(deleted).isTrue();
        assertThat(block(preregistrationRepository.findById(stored.id()))).isNull();
        assertThat(query("SELECT id FROM registration_ticket WHERE id = '" + ticket.id() + "'")).isEmpty();
    }

    @Test
    void registrationTicket_withoutAccountNorPreregistration_isRejectedByTheSchema() {
        // Act + Assert
        assertThatThrownBy(() -> sql("INSERT INTO registration_ticket (id, token_hash, expires_at) VALUES ('"
                + UUID.randomUUID() + "', '" + hash() + "', now())"))
                .hasMessageContaining("chk_registration_ticket_owner");
    }

    @Test
    void deleteExpired_emitsExpiredRowsAndKeepsLiveOnes() {
        // Arrange
        var live = insert(hash(), Duration.ofMinutes(5));
        var expiredTokenHash = hash();
        var expired = insert(expiredTokenHash, Duration.ofMinutes(5));
        var redeemedTokenHash = hash();
        var redeemed = insert(redeemedTokenHash, Duration.ofMinutes(5));
        block(preregistrationRepository.redeem(redeemedTokenHash));
        sql("UPDATE onboarding_preregistration SET expires_at = now() - interval '1 minute' WHERE id IN ('"
                + expired.id() + "', '" + redeemed.id() + "')");

        // Act
        var deleted = block(preregistrationRepository.deleteExpired());

        // Assert
        assertThat(deleted).contains(new ExpiredPreregistration(expired.id(), "system-a", false),
                new ExpiredPreregistration(redeemed.id(), "system-a", true));
        assertThat(deleted).extracting(ExpiredPreregistration::id).doesNotContain(live.id());
        assertThat(block(preregistrationRepository.findById(live.id()))).isNotNull();
    }

    @Test
    void disavowal_consume_isSingleUseAndCleanupDeletesIt() {
        // Arrange
        var userId = UUID.randomUUID();
        sql("INSERT INTO wallet_user (id, email) VALUES ('" + userId + "', 'disavow-" + System.nanoTime()
                + "@example.com')");
        var tokenHash = hash();
        block(disavowalRepository.insert(OnboardingDisavowal.issue(tokenHash, userId, null, "system-a",
                Instant.now(), false)));

        // Act
        var first = block(disavowalRepository.consume(tokenHash));
        var second = block(disavowalRepository.consume(tokenHash));
        var deleted = block(disavowalRepository.deleteConsumedOrExpired());

        // Assert
        assertThat(first).isNotNull();
        assertThat(first.userId()).isEqualTo(userId);
        assertThat(first.accountCreated()).isFalse();
        assertThat(first.consumedAt()).isNotNull();
        assertThat(first.expiresAt()).isAfter(Instant.now().plus(Duration.ofDays(6)));
        assertThat(second).isNull();
        assertThat(deleted).isPositive();
        assertThat(query("SELECT id FROM onboarding_disavowal WHERE token_hash = '" + tokenHash + "'")).isEmpty();
        assertThat(Objects.requireNonNull(first).passkeyId()).isNull();
    }
}
