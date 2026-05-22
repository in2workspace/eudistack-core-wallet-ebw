package com.eudistack.ebw.wallet.profile.infrastructure.web;

import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import com.eudistack.ebw.wallet.profile.infrastructure.observability.WalletProfileQueryTelemetry;
import io.r2dbc.spi.R2dbcException;
import io.r2dbc.spi.R2dbcTimeoutException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link WalletProfileQueryController} using
 * {@link WebTestClient#bindToController}.
 *
 * <p>Covers:
 * <ul>
 *   <li>ES-03: {@link IllegalArgumentException} → 500 {@code internal_error}
 *   <li>ES-04: {@link R2dbcException} → 503 {@code service_unavailable}
 *   <li>ES-05: {@link R2dbcTimeoutException} → 503 {@code service_unavailable}
 *   <li>DTO serialisation field-by-field
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class WalletProfileQueryControllerTest {

    @Mock
    private WalletProfileQueryPort walletProfileQueryPort;

    @Mock
    private WalletProfileQueryTelemetry telemetry;

    private WebTestClient webTestClient;

    private static final Instant NOW = Instant.parse("2026-05-22T10:00:00Z");

    @BeforeEach
    void setUp() {
        WalletProfileQueryController controller =
                new WalletProfileQueryController(walletProfileQueryPort, telemetry);
        WalletProfileQueryExceptionHandler handler =
                new WalletProfileQueryExceptionHandler(telemetry);

        webTestClient = WebTestClient.bindToController(controller)
                .controllerAdvice(handler)
                .build();

        // Telemetry calls do nothing in unit tests
        doNothing().when(telemetry).recordSuccess(anyString(), anyLong());
        doNothing().when(telemetry).recordError(anyString(), any(Throwable.class), anyLong());
        doNothing().when(telemetry).recordNotFound(anyString(), any(), anyLong());
    }

    @Test
    void getWalletConfigMetadata_illegalArgumentException_returns500InternalError() {
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.error(new IllegalArgumentException("invariant violated")));

        webTestClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR)
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody()
                .jsonPath("$.error").isEqualTo("internal_error");
    }

    @Test
    void getWalletConfigMetadata_r2dbcException_returns503ServiceUnavailable() {
        R2dbcException r2dbcException = new R2dbcException("connection refused", "08001") {};
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.error(r2dbcException));

        webTestClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.SERVICE_UNAVAILABLE)
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody()
                .jsonPath("$.error").isEqualTo("service_unavailable");
    }

    @Test
    void getWalletConfigMetadata_r2dbcTimeoutException_returns503ServiceUnavailable() {
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.error(new R2dbcTimeoutException("statement timeout", "08006")));

        webTestClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.SERVICE_UNAVAILABLE)
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody()
                .jsonPath("$.error").isEqualTo("service_unavailable");
    }

    @Test
    void getWalletConfigMetadata_browserProfile_serialisesAllFields() {
        TenantWalletProfile profile =
                new TenantWalletProfile("sandbox", WalletMode.BROWSER, null, NOW, NOW);
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(profile));

        webTestClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody()
                .jsonPath("$.wallet_mode").isEqualTo("browser")
                .jsonPath("$.key_manager").doesNotExist();
    }

    @Test
    void getWalletConfigMetadata_serverProfileWithHsm_serialisesAllFields() {
        TenantWalletProfile profile =
                new TenantWalletProfile("kpmg", WalletMode.SERVER, KeyManager.HSM, NOW, NOW);
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(profile));

        webTestClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.wallet_mode").isEqualTo("server")
                .jsonPath("$.key_manager").isEqualTo("hsm");
    }

    @Test
    void getWalletConfigMetadata_success_includesSecurityHeaders() {
        TenantWalletProfile profile =
                new TenantWalletProfile("sandbox", WalletMode.BROWSER, null, NOW, NOW);
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(profile));

        webTestClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Cache-Control", "public, max-age=60, must-revalidate")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("Referrer-Policy", "no-referrer");
    }

    @Test
    void getWalletConfigMetadata_error_includesSecurityHeaders() {
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.error(new TenantUnknownException(
                        TenantUnknownException.Reason.PROFILE_NOT_SEEDED)));

        webTestClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .exchange()
                .expectStatus().isNotFound()
                .expectHeader().valueEquals("Cache-Control", "public, max-age=60, must-revalidate")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("Referrer-Policy", "no-referrer");
    }
}
