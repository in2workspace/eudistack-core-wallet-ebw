package com.eudistack.ebw.wallet.profile.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.infrastructure.adapter.r2dbc.entity.TenantWalletProfileEntity;
import com.eudistack.ebw.wallet.profile.infrastructure.adapter.r2dbc.spring.SpringTenantWalletProfileRepository;
import io.r2dbc.spi.R2dbcNonTransientResourceException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit test for {@link R2dbcWalletProfileReadAdapter}.
 *
 * <p>Covers the adapter's contract in full isolation — no Spring context,
 * no database. {@link SpringTenantWalletProfileRepository} is replaced by a
 * Mockito mock so every scenario is exercised without network I/O.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>ES-04 — connection error propagates unchanged as an error signal
 *       (the adapter does NOT mask it as {@link Mono#empty()})</li>
 *   <li>ES-02 — {@link Mono#empty()} from the repository is forwarded
 *       unchanged to the caller</li>
 *   <li>AC-07 (mapping) — inline entity-to-record mapping is correct for
 *       both browser and server modes</li>
 * </ul>
 *
 * @see R2dbcWalletProfileReadAdapterIT for the companion integration test
 *      that exercises the adapter with a real PostgreSQL container
 */
class R2dbcWalletProfileReadAdapterTest {

    private SpringTenantWalletProfileRepository repository;
    private R2dbcWalletProfileReadAdapter adapter;

    @BeforeEach
    void setUp() {
        repository = mock(SpringTenantWalletProfileRepository.class);
        adapter = new R2dbcWalletProfileReadAdapter(repository);
    }

    // -------------------------------------------------------------------------
    // ES-04 — connection refused error propagates as typed error signal
    // -------------------------------------------------------------------------

    /**
     * ES-04: When the R2DBC driver cannot reach the database (connection refused),
     * the repository emits an error signal. The adapter MUST propagate that error
     * unchanged — it must NOT convert it to {@link Mono#empty()} or swallow it.
     *
     * <p>Spec ref: acceptance-criteria.md ES-04 ("the adapter does not mask the
     * error as Mono.empty()").
     */
    @Test
    void findCurrent_propagates_r2dbc_connection_error_unchanged() {
        R2dbcNonTransientResourceException connectionError =
                new R2dbcNonTransientResourceException("Connection refused: database not available");
        when(repository.findFirstBy()).thenReturn(Mono.error(connectionError));

        StepVerifier.create(adapter.findCurrent())
                .as("adapter must propagate the R2DBC connection error without masking it")
                .expectError(R2dbcNonTransientResourceException.class)
                .verify();
    }

    /**
     * ES-04 (error identity): The propagated error must be the exact same instance
     * returned by the repository, preserving message and type for the caller to
     * log and handle.
     */
    @Test
    void findCurrent_propagates_r2dbc_error_with_original_message() {
        String originalMessage = "Connection refused: database not available";
        R2dbcNonTransientResourceException connectionError =
                new R2dbcNonTransientResourceException(originalMessage);
        when(repository.findFirstBy()).thenReturn(Mono.error(connectionError));

        StepVerifier.create(adapter.findCurrent())
                .as("propagated error must preserve the original exception message")
                .expectErrorSatisfies(thrown ->
                        assertThat(thrown.getMessage()).contains("Connection refused"))
                .verify();
    }

    // -------------------------------------------------------------------------
    // ES-02 — Mono.empty() from repository is forwarded unchanged
    // -------------------------------------------------------------------------

    /**
     * ES-02: When the repository returns {@link Mono#empty()} (no row for the
     * current tenant schema), the adapter must propagate {@link Mono#empty()}
     * without emitting an error or a default value.
     *
     * <p>Spec ref: acceptance-criteria.md ES-02 ("the port returns Mono.empty(),
     * NOT Mono.error").
     */
    @Test
    void findCurrent_propagates_mono_empty_when_repository_returns_empty() {
        when(repository.findFirstBy()).thenReturn(Mono.empty());

        StepVerifier.create(adapter.findCurrent())
                .as("adapter must propagate Mono.empty() unchanged when repository is empty")
                .verifyComplete(); // no item emitted, no error
    }

    // -------------------------------------------------------------------------
    // AC-07 (inline mapping) — entity → record for browser mode
    // -------------------------------------------------------------------------

    /**
     * AC-07 (browser mapping): When the repository returns a browser-mode entity
     * with {@code key_manager = null}, the adapter maps it to a
     * {@link com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile}
     * with {@code walletMode=BROWSER} and {@code keyManager=null}.
     */
    @Test
    void findCurrent_maps_browser_entity_to_domain_record_correctly() {
        Instant now = Instant.now();
        TenantWalletProfileEntity entity = new TenantWalletProfileEntity(
                "sandbox", "browser", null, now, now);
        when(repository.findFirstBy()).thenReturn(Mono.just(entity));

        StepVerifier.create(adapter.findCurrent())
                .assertNext(profile -> {
                    assertThat(profile.tenant())
                            .as("tenant must match the entity value")
                            .isEqualTo("sandbox");
                    assertThat(profile.walletMode())
                            .as("walletMode must be BROWSER")
                            .isEqualTo(WalletMode.BROWSER);
                    assertThat(profile.keyManager())
                            .as("keyManager must be null for BROWSER mode")
                            .isNull();
                    assertThat(profile.createdAt())
                            .as("createdAt must be propagated from entity")
                            .isEqualTo(now);
                    assertThat(profile.updatedAt())
                            .as("updatedAt must be propagated from entity")
                            .isEqualTo(now);
                })
                .verifyComplete();
    }

    // -------------------------------------------------------------------------
    // AC-07 (inline mapping) — entity → record for server mode
    // -------------------------------------------------------------------------

    /**
     * AC-07 (server mapping): When the repository returns a server-mode entity
     * with {@code key_manager = 'db'}, the adapter maps it to a profile with
     * {@code walletMode=SERVER} and {@code keyManager=DB}.
     */
    @Test
    void findCurrent_maps_server_db_entity_to_domain_record_correctly() {
        Instant now = Instant.now();
        TenantWalletProfileEntity entity = new TenantWalletProfileEntity(
                "dome", "server", "db", now, now);
        when(repository.findFirstBy()).thenReturn(Mono.just(entity));

        StepVerifier.create(adapter.findCurrent())
                .assertNext(profile -> {
                    assertThat(profile.tenant())
                            .as("tenant must be 'dome'")
                            .isEqualTo("dome");
                    assertThat(profile.walletMode())
                            .as("walletMode must be SERVER")
                            .isEqualTo(WalletMode.SERVER);
                    assertThat(profile.keyManager())
                            .as("keyManager must be DB")
                            .isEqualTo(KeyManager.DB);
                })
                .verifyComplete();
    }

    /**
     * AC-07 (server/hsm variant): Verifies mapping for {@code key_manager='hsm'}.
     */
    @Test
    void findCurrent_maps_server_hsm_entity_to_domain_record_correctly() {
        Instant now = Instant.now();
        TenantWalletProfileEntity entity = new TenantWalletProfileEntity(
                "kpmg", "server", "hsm", now, now);
        when(repository.findFirstBy()).thenReturn(Mono.just(entity));

        StepVerifier.create(adapter.findCurrent())
                .assertNext(profile -> {
                    assertThat(profile.walletMode()).isEqualTo(WalletMode.SERVER);
                    assertThat(profile.keyManager()).isEqualTo(KeyManager.HSM);
                })
                .verifyComplete();
    }
}