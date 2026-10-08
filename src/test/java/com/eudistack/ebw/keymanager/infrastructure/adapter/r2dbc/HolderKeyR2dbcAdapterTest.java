package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.entity.HolderKeyEntity;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.spring.SpringHolderKeyRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2dbc.postgresql.codec.Json;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.test.publisher.PublisherProbe;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link HolderKeyR2dbcAdapter} — tenant + holder scoped lookups, the UPSERT-ON-CONFLICT
 * idempotency path (EC-01 / ADR-021) and the JSONB public JWK codec. The SQL itself runs against PostgreSQL in
 * {@code HolderKeyR2dbcAdapterIT}.
 */
class HolderKeyR2dbcAdapterTest {

    private static final String TENANT = "sandbox";
    private static final String HOLDER = "holder-1";
    private static final String CREDENTIAL = "cred-1";
    private static final Instant CREATED_AT = Instant.parse("2026-05-26T10:00:00Z");
    private static final Map<String, Object> JWK = Map.of("kty", "EC", "crv", "P-256", "x", "abc", "y", "def");

    private SpringHolderKeyRepository repository;
    private DatabaseClientStub db;
    private HolderKeyR2dbcAdapter adapter;

    @BeforeEach
    void setUp() {
        repository = mock(SpringHolderKeyRepository.class);
        db = new DatabaseClientStub();
        adapter = new HolderKeyR2dbcAdapter(repository, new ObjectMapper(), db.client);
    }

    @Test
    void findBy_activeKey_mapsTheEntityToTheDomain() {
        // Arrange
        var key = holderKey(null);
        when(repository.findFirstByTenantIdAndHolderIdAndCredentialIdAndRevokedAtIsNull(TENANT, HOLDER, CREDENTIAL))
                .thenReturn(Mono.just(entity(key, "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"abc\",\"y\":\"def\"}")));

        // Act
        var result = adapter.findBy(TENANT, HOLDER, CREDENTIAL);

        // Assert
        StepVerifier.create(result)
                .assertNext(found -> {
                    assertThat(found.id()).isEqualTo(key.id());
                    assertThat(found.format()).isEqualTo(CredentialFormat.SD_JWT_VC);
                    assertThat(found.algorithm()).isEqualTo(KeyAlgorithm.ES256);
                    assertThat(found.privateKey()).containsExactly(1, 2, 3);
                    assertThat(found.publicJwk().claims()).isEqualTo(JWK);
                    assertThat(found.createdAt()).isEqualTo(CREATED_AT);
                })
                .verifyComplete();
    }

    @Test
    void findById_scopesTheLookupByTenantHolderAndKeyId() {
        // Arrange
        var key = holderKey(null);
        when(repository.findFirstByTenantIdAndHolderIdAndKeyIdAndRevokedAtIsNull(TENANT, HOLDER,
                key.id().value().toString())).thenReturn(Mono.empty());

        // Act
        var result = adapter.findById(TENANT, HOLDER, key.id());

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(repository).findFirstByTenantIdAndHolderIdAndKeyIdAndRevokedAtIsNull(TENANT, HOLDER,
                key.id().value().toString());
    }

    @Test
    void findBy_corruptPublicJwk_failsWithIllegalState() {
        // Arrange
        when(repository.findFirstByTenantIdAndHolderIdAndCredentialIdAndRevokedAtIsNull(TENANT, HOLDER, CREDENTIAL))
                .thenReturn(Mono.just(entity(holderKey(null), "{broken")));

        // Act
        var result = adapter.findBy(TENANT, HOLDER, CREDENTIAL);

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof IllegalStateException
                        && e.getMessage().equals("Failed to deserialize public JWK from database"))
                .verify();
    }

    @Test
    void upsertIfAbsent_insertReturnsTheKeyId_reportsCreatedWithoutReReading() {
        // Arrange
        var key = holderKey(null);
        var fallbackRead = PublisherProbe.<HolderKeyEntity>empty();
        when(db.row.get("key_id", String.class)).thenReturn(key.id().value().toString());
        when(repository.findFirstByTenantIdAndHolderIdAndCredentialIdAndRevokedAtIsNull(TENANT, HOLDER, CREDENTIAL))
                .thenReturn(fallbackRead.mono());

        // Act
        var result = adapter.upsertIfAbsent(key);

        // Assert
        StepVerifier.create(result)
                .assertNext(persisted -> {
                    assertThat(persisted.created()).isTrue();
                    assertThat(persisted.holderKey().id()).isEqualTo(key.id());
                    assertThat(persisted.holderKey().publicJwk().claims()).isEqualTo(JWK);
                })
                .verifyComplete();
        assertThat(db.executedSql.get(0)).contains("ON CONFLICT ON CONSTRAINT uq_holder_key_tenant_holder_credential");
        assertThat(db.bindings)
                .containsEntry("keyId", key.id().value().toString())
                .containsEntry("tenantId", TENANT)
                .containsEntry("holderId", HOLDER)
                .containsEntry("credentialId", CREDENTIAL)
                .containsEntry("algorithm", "ES256")
                .containsEntry("format", "dc+sd-jwt")
                .containsEntry("createdAt", CREATED_AT)
                .containsEntry("revokedAt", null);
        fallbackRead.assertWasNotSubscribed();
    }

    @Test
    void upsertIfAbsent_conflictWithExistingRow_returnsTheCanonicalKeyAsNotCreated() {
        // Arrange
        var candidate = holderKey(null);
        var existing = holderKey(null);
        db.rowPresent = false;
        when(repository.findFirstByTenantIdAndHolderIdAndCredentialIdAndRevokedAtIsNull(TENANT, HOLDER, CREDENTIAL))
                .thenReturn(Mono.just(entity(existing, "{\"kty\":\"EC\"}")));

        // Act
        var result = adapter.upsertIfAbsent(candidate);

        // Assert
        StepVerifier.create(result)
                .assertNext(persisted -> {
                    assertThat(persisted.created()).isFalse();
                    assertThat(persisted.holderKey().id()).isEqualTo(existing.id());
                })
                .verifyComplete();
    }

    @Test
    void upsertIfAbsent_revokedKey_bindsTheRevocationInstant() {
        // Arrange
        var revokedAt = CREATED_AT.plusSeconds(60);
        var key = holderKey(revokedAt);
        when(db.row.get("key_id", String.class)).thenReturn(key.id().value().toString());
        when(repository.findFirstByTenantIdAndHolderIdAndCredentialIdAndRevokedAtIsNull(TENANT, HOLDER, CREDENTIAL))
                .thenReturn(Mono.empty());

        // Act
        var result = adapter.upsertIfAbsent(key);

        // Assert
        StepVerifier.create(result)
                .assertNext(persisted -> assertThat(persisted.holderKey().revokedAt()).isEqualTo(revokedAt))
                .verifyComplete();
        assertThat(db.bindings).containsEntry("revokedAt", revokedAt);
    }

    @Test
    void upsertIfAbsent_jwkCannotBeSerialized_failsWithIllegalState() throws JsonProcessingException {
        // Arrange
        var failingMapper = mock(ObjectMapper.class);
        when(failingMapper.writeValueAsString(any())).thenThrow(new JsonProcessingException("boom") { });
        var failingAdapter = new HolderKeyR2dbcAdapter(repository, failingMapper, db.client);
        var key = holderKey(null);

        // Act + Assert
        assertThatThrownBy(() -> failingAdapter.upsertIfAbsent(key))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Failed to serialize public JWK for database");
    }

    private static HolderKey holderKey(Instant revokedAt) {
        return new HolderKey(HolderKeyId.generate(), TENANT, HOLDER, CREDENTIAL, CredentialFormat.SD_JWT_VC,
                KeyAlgorithm.ES256, new byte[]{1, 2, 3}, new JwkPublic(JWK), CREATED_AT, revokedAt);
    }

    private static HolderKeyEntity entity(HolderKey key, String jwkJson) {
        var entity = new HolderKeyEntity();
        entity.setKeyId(key.id().value().toString());
        entity.setTenantId(key.tenantId());
        entity.setHolderId(key.holderId());
        entity.setCredentialId(key.credentialId());
        entity.setPrivateKey(key.privateKey());
        entity.setPublicJwk(Json.of(jwkJson));
        entity.setAlgorithm(key.algorithm().name());
        entity.setFormat(key.format().dbValue());
        entity.setCreatedAt(key.createdAt());
        entity.setRevokedAt(key.revokedAt());
        return entity;
    }
}
