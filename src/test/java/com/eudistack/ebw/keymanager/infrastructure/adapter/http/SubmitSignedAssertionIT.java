package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.keymanager.application.PrfSaltUseCase;
import com.eudistack.ebw.keymanager.domain.model.WrappedKeyHandle;
import com.eudistack.ebw.keymanager.domain.port.WrappedKeyHandleRepository;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Integration tests for {@code POST /api/v1/keys/hybrid/sign/submit}.
 *
 * <p>Also covers T13 (holder isolation — H2 cannot submit with H1's correlation_id)
 * and T14 (NFR-S-536-03/04 no-leak in error responses).</p>
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-02 — valid holder signature → 200 + {@code kb_jwt} = {@code signing_input.signature}.</li>
 *   <li>EC-03 — idempotent replay of the same {@code correlation_id} → same {@code kb_jwt}.</li>
 *   <li>ES-01 — unknown/expired {@code correlation_id} → 400 {@code invalid_request}.</li>
 *   <li>ES-03 — signature from wrong key → 400 {@code signature_invalid}.</li>
 *   <li>ES-04 / AC-08 — H2 submits with H1's {@code correlation_id} → 403 opaque.</li>
 *   <li>NFR-S-536-03 — error bodies MUST NOT contain {@code prf_salt}, {@code wrapped_blob}.</li>
 * </ul>
 *
 * <p>Uses real EC P-256 crypto (Nimbus). {@link PrfSaltUseCase} and
 * {@link WrappedKeyHandleRepository} are mocked so only the HTTP + use-case contract
 * is under test.</p>
 *
 * <p>Spec: EUDISTACK-536 AC-02, AC-08, AC-09, EC-03, ES-01, ES-03, ES-04,
 * NFR-S-536-03; architecture.md §6.3.</p>
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.autoconfigure.exclude=", "ebw.tenant-flyway.enabled=false"}
)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
class SubmitSignedAssertionIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String HYBRID_TENANT = "hsubmit";
    private static final String DB_TENANT     = "hsubmitdb";
    private static final UUID   H1_UUID       = UUID.fromString("11111111-bbbb-cccc-dddd-eeeeeeeeeeee");
    private static final UUID   H2_UUID       = UUID.fromString("22222222-bbbb-cccc-dddd-eeeeeeeeeeee");
    private static final String H1_BEARER     = "submit-h1-bearer";
    private static final String H2_BEARER     = "submit-h2-bearer";
    private static final String PREPARE_URL   = "/api/v1/keys/hybrid/sign/prepare";
    private static final String SUBMIT_URL    = "/api/v1/keys/hybrid/sign/submit";
    private static final String CRED_ID       = "cred-submit-1";

    private static final byte[] PRF_SALT   = new byte[32];
    private static final byte[] BLOB_BYTES = new byte[48];
    private static final byte[] IV_BYTES   = new byte[12];
    private static final byte[] TAG_BYTES  = new byte[16];

    /** Holder-1 real P-256 key pair. cnfJwk is the public JWK stored in the WrappedKeyHandle mock. */
    private static ECKey holderKey;
    private static String cnfJwk;

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("submit_signed_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/submit_signed_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/submit_signed_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
    }

    @MockitoBean TokenSigner tokenSigner;
    @MockitoBean PrfSaltUseCase prfSaltUseCase;
    @MockitoBean WrappedKeyHandleRepository wrappedKeyHandleRepository;

    @Autowired WebTestClient webClient;

    @BeforeAll
    static void generateHolderKeyAndProvisionSchemas() throws Exception {
        holderKey = new ECKeyGenerator(Curve.P_256).generate();
        cnfJwk = holderKey.toPublicJWK().toJSONString();

        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "CREATE SCHEMA IF NOT EXISTS " + HYBRID_TENANT + SCHEMA_SUFFIX);
            conn.createStatement().execute(
                    "CREATE SCHEMA IF NOT EXISTS " + DB_TENANT + SCHEMA_SUFFIX);
        }
        runTenantMigrations(jdbcUrl, HYBRID_TENANT + SCHEMA_SUFFIX);
        runTenantMigrations(jdbcUrl, DB_TENANT + SCHEMA_SUFFIX);
    }

    private static void runTenantMigrations(String jdbcUrl, String schema) {
        Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(schema)
                .schemas(schema)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    @BeforeEach
    void setUp() throws SQLException {
        seedWalletProfile(HYBRID_TENANT, "server", "hybrid");
        seedWalletProfile(DB_TENANT, "server", "db");
        when(tokenSigner.verify(H1_BEARER)).thenReturn(
                Map.of("sub", H1_UUID.toString(), "email", "h1@test.com"));
        when(tokenSigner.verify(H2_BEARER)).thenReturn(
                Map.of("sub", H2_UUID.toString(), "email", "h2@test.com"));
        when(prfSaltUseCase.getForHolder(any(), any(), any())).thenReturn(Mono.just(PRF_SALT));
        when(wrappedKeyHandleRepository.findBy(any(), any()))
                .thenReturn(Mono.just(Optional.of(validHandleFor(H1_UUID))));
    }

    // ------------------------------------------------------------------ AC-02

    @Test
    void submit_validSignature_returns200WithKbJwt() throws Exception {
        Map<String, Object> prepare = callPrepare(H1_BEARER);
        String signingInput = (String) prepare.get("signing_input");
        String correlationId = (String) prepare.get("correlation_id");
        String signature = signWithHolderKey(signingInput);

        webClient.post().uri(SUBMIT_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + H1_BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of(
                        "credential_id", CRED_ID,
                        "signature", signature,
                        "correlation_id", correlationId))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.kb_jwt").value((String kbJwt) -> {
                    assertThat(kbJwt).as("kb_jwt must be signingInput.signature")
                            .startsWith(signingInput + ".");
                    assertThat(kbJwt.split("\\.")).as("kb_jwt must have 3 parts").hasSize(3);
                });
    }

    // ------------------------------------------------------------------ EC-03

    @Test
    void submit_idempotentReplay_returnsSameKbJwt() throws Exception {
        Map<String, Object> prepare = callPrepare(H1_BEARER);
        String signingInput = (String) prepare.get("signing_input");
        String correlationId = (String) prepare.get("correlation_id");
        String signature = signWithHolderKey(signingInput);

        Map<String, Object> first = callSubmit(H1_BEARER, correlationId, signature);
        Map<String, Object> second = callSubmit(H1_BEARER, correlationId, signature);

        assertThat(first.get("kb_jwt")).isEqualTo(second.get("kb_jwt"));
    }

    // ------------------------------------------------------------------ ES-01

    @Test
    void submit_unknownCorrelationId_returns400InvalidRequest() {
        // Use case rejects on store miss before parsing the signature,
        // so any plausible base64url value works here.
        String dummySig = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        webClient.post().uri(SUBMIT_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + H1_BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of(
                        "credential_id", CRED_ID,
                        "signature", dummySig,
                        "correlation_id", UUID.randomUUID().toString()))
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("invalid_request");
    }

    // ------------------------------------------------------------------ ES-03

    @Test
    void submit_signatureFromDifferentKey_returns400SignatureInvalid() throws Exception {
        Map<String, Object> prepare = callPrepare(H1_BEARER);
        String signingInput = (String) prepare.get("signing_input");
        String correlationId = (String) prepare.get("correlation_id");

        ECKey attackerKey = new ECKeyGenerator(Curve.P_256).generate();
        String forgedSig = signWith(signingInput, attackerKey);

        webClient.post().uri(SUBMIT_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + H1_BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of(
                        "credential_id", CRED_ID,
                        "signature", forgedSig,
                        "correlation_id", correlationId))
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("signature_invalid");
    }

    // ------------------------------------------------------------------ ES-04 / AC-08 (T13)

    @Test
    void submit_differentHolderUsesH1CorrelationId_returns403() throws Exception {
        Map<String, Object> prepare = callPrepare(H1_BEARER);
        String signingInput = (String) prepare.get("signing_input");
        String correlationId = (String) prepare.get("correlation_id");
        String signature = signWithHolderKey(signingInput);

        webClient.post().uri(SUBMIT_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + H2_BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of(
                        "credential_id", CRED_ID,
                        "signature", signature,
                        "correlation_id", correlationId))
                .exchange()
                .expectStatus().isForbidden();
    }

    // ------------------------------------------------------------------ NFR-S-536-03 (T14)

    @Test
    void submit_errorResponse_doesNotLeakCryptoMaterial() {
        String dummySig = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        webClient.post().uri(SUBMIT_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + H1_BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of(
                        "credential_id", CRED_ID,
                        "signature", dummySig,
                        "correlation_id", UUID.randomUUID().toString()))
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody(String.class)
                .value(body -> {
                    assertThat(body).as("NFR-S-536-03: error body must not contain prf_salt")
                            .doesNotContain("prf_salt");
                    assertThat(body).as("NFR-S-536-03: error body must not contain wrapped_blob")
                            .doesNotContain("wrapped_blob");
                });
    }

    // ------------------------------------------------------------------ helpers

    /**
     * Calls /prepare and returns the parsed response body.
     * Extracted to avoid repeating the WebTestClient chain in every test.
     */
    private Map<String, Object> callPrepare(String bearer) {
        return webClient.post().uri(PREPARE_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + bearer)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("credential_id", CRED_ID, "payload",
                        Map.of("nonce", "vp-nonce", "iat", 1_700_000_000, "aud", "https://verifier.example", "sd_hash", "test-sd-hash"),
                        "format", "vc+sd-jwt"))
                .exchange()
                .expectStatus().isOk()
                .expectBody(new ParameterizedTypeReference<Map<String, Object>>() {})
                .returnResult()
                .getResponseBody();
    }

    /**
     * Calls /submit and returns the parsed response body (expects 200).
     */
    private Map<String, Object> callSubmit(String bearer, String correlationId, String signature) {
        return webClient.post().uri(SUBMIT_URL)
                .header("Host", HYBRID_TENANT + ".eudistack.net")
                .header("Authorization", "Bearer " + bearer)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of(
                        "credential_id", CRED_ID,
                        "signature", signature,
                        "correlation_id", correlationId))
                .exchange()
                .expectStatus().isOk()
                .expectBody(new ParameterizedTypeReference<Map<String, Object>>() {})
                .returnResult()
                .getResponseBody();
    }

    /**
     * Signs {@code signingInput} (headerB64url.payloadB64url) using the holder's EC key.
     *
     * <p>Splits into two base64url parts, reconstructs the JWSObject preserving the original
     * base64url encoding (Nimbus caches it on parse), signs with P-256 ECDSA, and returns
     * the detached base64url signature (third JWS compact part).</p>
     */
    private String signWithHolderKey(String signingInput) throws Exception {
        return signWith(signingInput, holderKey);
    }

    private String signWith(String signingInput, ECKey key) throws Exception {
        String[] parts = signingInput.split("\\.");
        JWSHeader header = JWSHeader.parse(new Base64URL(parts[0]));
        Payload payload = new Payload(new Base64URL(parts[1]));
        JWSObject jwsObject = new JWSObject(header, payload);
        jwsObject.sign(new ECDSASigner(key));
        return jwsObject.serialize().split("\\.")[2];
    }

    private WrappedKeyHandle validHandleFor(UUID holderUuid) {
        return new WrappedKeyHandle(
                holderUuid.toString(), CRED_ID, BLOB_BYTES, IV_BYTES, TAG_BYTES,
                "HKDF-SHA-256", 1, cnfJwk, Instant.now(), null);
    }

    private void seedWalletProfile(String tenant, String mode, String km) throws SQLException {
        String schema = tenant + SCHEMA_SUFFIX;
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "DELETE FROM " + schema + ".tenant_wallet_profile WHERE tenant = '" + tenant + "'");
            conn.createStatement().execute(
                    "INSERT INTO " + schema + ".tenant_wallet_profile (tenant, wallet_mode, key_manager) "
                    + "VALUES ('" + tenant + "', '" + mode + "', '" + km + "') "
                    + "ON CONFLICT (tenant) DO NOTHING");
        }
    }
}
