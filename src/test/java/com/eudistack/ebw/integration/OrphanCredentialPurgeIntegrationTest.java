package com.eudistack.ebw.integration;

import com.eudistack.ebw.domain.model.CredentialFormat;
import com.eudistack.ebw.domain.model.CustodyMode;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.infrastructure.configuration.OrphanCredentialPurgeJob;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs {@link OrphanCredentialPurgeJob} against the database (EUD-328 FR-25, AC-24): the expired orphans of a
 * tenant with passkey custody are deleted and audited, the rest are kept, and nothing is deleted with server
 * custody. The attestations have no key material, so only the row and the audit event are observed.
 */
class OrphanCredentialPurgeIntegrationTest extends IntegrationTestBase {

    @Autowired private OrphanCredentialPurgeJob job;
    @Autowired private WalletCredentialRepository credentialRepository;

    private UUID userId;
    private boolean tenantRegisteredByThisTest;

    @BeforeEach
    void setUp() {
        var email = "orphan-purge-" + System.nanoTime() + "@test.com";
        getAccessToken(email);
        userId = (UUID) query("SELECT id FROM wallet_user WHERE email = '" + email + "'").get(0).get("id");

        // The job lists the active tenants of the registry, which the integration tenant is not part of.
        tenantRegisteredByThisTest = query("SELECT 1 AS one FROM public.tenant_registry WHERE schema_name = '"
                + TEST_TENANT + "'").isEmpty();
        sql("INSERT INTO public.tenant_registry (schema_name, display_name) VALUES ('" + TEST_TENANT
                + "', 'Integration test') ON CONFLICT (schema_name) DO UPDATE SET status = 'active'");
    }

    @AfterEach
    void tearDown() {
        if (tenantRegisteredByThisTest) {
            sql("DELETE FROM public.tenant_registry WHERE schema_name = '" + TEST_TENANT + "'");
        }
    }

    @Nested
    @DisplayName("purge with passkey custody")
    class PasskeyCustody {

        @Test
        @DisplayName("deletes the expired orphans and audits each one with its reason")
        void purge_expiredOrphans_deletesThemAndRecordsOneDeletedEventEach() {
            // Arrange
            var now = Instant.now();
            var expired = seed(true, CustodyMode.PASSKEY, now.minus(Duration.ofDays(1)));
            var expiredLonger = seed(true, CustodyMode.PASSKEY, now.minus(Duration.ofDays(30)));

            // Act
            PasskeyRegistrationIT.withPasskeyCustody(() -> job.purge().block());

            // Assert
            assertThat(remaining(expired, expiredLonger)).isEmpty();
            for (var id : new UUID[] {expired, expiredLonger}) {
                var events = deletedEvents(id);
                assertThat(events).hasSize(1);
                assertThat(events.get(0).get("actor_id")).as("the service, not a user, deleted it").isNull();
                assertThat((String) events.get(0).get("metadata")).contains("orphan_expired");
            }
        }

        @Test
        @DisplayName("keeps the orphan that has not expired, the one without expiration date and the unbound one")
        void purge_attestationsThatAreNotExpiredOrphans_areKept() {
            // Arrange
            var now = Instant.now();
            var notExpired = seed(true, CustodyMode.PASSKEY, now.plus(Duration.ofDays(1)));
            var withoutExpiration = seed(true, CustodyMode.PASSKEY, null);
            var unboundExpired = seed(false, null, now.minus(Duration.ofDays(1)));

            // Act
            PasskeyRegistrationIT.withPasskeyCustody(() -> job.purge().block());

            // Assert
            assertThat(remaining(notExpired, withoutExpiration, unboundExpired))
                    .containsExactlyInAnyOrder(notExpired, withoutExpiration, unboundExpired);
            assertThat(deletedEvents(notExpired)).isEmpty();
        }

        @Test
        @DisplayName("keeps an expired server-custody attestation of a tenant that changed to passkey custody")
        void purge_serverCustodyAttestation_isNotTreatedAsOrphan() {
            // Arrange
            var serverCustody = seed(true, CustodyMode.SERVER, Instant.now().minus(Duration.ofDays(1)));

            // Act
            PasskeyRegistrationIT.withPasskeyCustody(() -> job.purge().block());

            // Assert
            assertThat(remaining(serverCustody)).containsExactly(serverCustody);
        }

        @Test
        @DisplayName("a second run finds nothing more and does not audit again")
        void purge_runTwice_recordsASingleDeletedEvent() {
            // Arrange
            var expired = seed(true, CustodyMode.PASSKEY, Instant.now().minus(Duration.ofDays(1)));

            // Act
            PasskeyRegistrationIT.withPasskeyCustody(() -> {
                job.purge().block();
                job.purge().block();
            });

            // Assert
            assertThat(deletedEvents(expired)).hasSize(1);
        }
    }

    @Nested
    @DisplayName("purge with server custody")
    class ServerCustody {

        @Test
        @DisplayName("deletes nothing, not even an expired orphan")
        void purge_serverCustodyTenant_deletesNothing() {
            // Arrange
            var expiredOrphan = seed(true, CustodyMode.PASSKEY, Instant.now().minus(Duration.ofDays(1)));
            var expiredServerCustody = seed(true, CustodyMode.SERVER, Instant.now().minus(Duration.ofDays(1)));

            // Act
            withServerCustody(() -> job.purge().block());

            // Assert
            assertThat(remaining(expiredOrphan, expiredServerCustody))
                    .containsExactlyInAnyOrder(expiredOrphan, expiredServerCustody);
            assertThat(deletedEvents(expiredOrphan)).isEmpty();
        }
    }

    private UUID seed(boolean bound, CustodyMode custodyMode, Instant expirationDate) {
        var suffix = System.nanoTime();
        var credential = WalletCredential.create(userId, "raw-" + suffix, CredentialFormat.JWT_VC_JSON,
                "config-purge-" + suffix, "kid-purge-" + suffix, "TestCredential", null,
                "https://issuer-purge.com", "did:example:purge", Instant.now().minus(Duration.ofDays(60)),
                expirationDate, Map.of(), null, bound, null, custodyMode);
        return credentialRepository.insert(credential)
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT))
                .block()
                .getId();
    }

    private static Set<UUID> remaining(UUID... ids) {
        var list = Arrays.stream(ids).map(id -> "'" + id + "'").collect(Collectors.joining(","));
        return query("SELECT id FROM wallet_credential WHERE id IN (" + list + ")").stream()
                .map(row -> (UUID) row.get("id"))
                .collect(Collectors.toSet());
    }

    private static java.util.List<Map<String, Object>> deletedEvents(UUID credentialId) {
        return query("SELECT actor_id, metadata FROM audit_log WHERE entity_type = 'credential' AND entity_id = '"
                + credentialId + "' AND action = 'DELETED'");
    }

    /** Runs with the test tenant in server custody (server + db), then restores it. */
    private static void withServerCustody(Runnable action) {
        sql("INSERT INTO tenant_wallet_profile (tenant, wallet_mode, key_manager) VALUES ('" + TEST_TENANT
                + "', 'server', 'db') ON CONFLICT (tenant) DO UPDATE SET wallet_mode = 'server', key_manager = 'db'");
        try {
            action.run();
        } finally {
            sql("DELETE FROM tenant_wallet_profile WHERE tenant = '" + TEST_TENANT + "'");
        }
    }
}
