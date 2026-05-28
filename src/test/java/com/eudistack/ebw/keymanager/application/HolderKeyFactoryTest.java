package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.PlaintextHandle;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class HolderKeyFactoryTest {

    private HolderKeyFactory factory;

    @BeforeEach
    void setUp() {
        factory = new HolderKeyFactory();
    }

    // --- generate ---

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void generate_producesNonNullResult(KeyAlgorithm algorithm) {
        GeneratedKeyPair result = factory.generate(algorithm);
        assertThat(result).isNotNull();
        assertThat(result.privateKeyHandle()).isNotNull();
        assertThat(result.publicJwk()).isNotNull();
        assertThat(result.rawPrivateBytes()).isNotNull().isNotEmpty();
    }

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void generate_publicJwk_hasCorrectKty(KeyAlgorithm algorithm) {
        GeneratedKeyPair result = factory.generate(algorithm);
        String kty = (String) result.publicJwk().claims().get("kty");
        if (algorithm == KeyAlgorithm.EdDSA) {
            assertThat(kty).isEqualTo("OKP");
        } else {
            assertThat(kty).isEqualTo("EC");
        }
    }

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void generate_publicJwk_hasCorrectCurve(KeyAlgorithm algorithm) {
        GeneratedKeyPair result = factory.generate(algorithm);
        String crv = (String) result.publicJwk().claims().get("crv");
        assertThat(crv).isEqualTo(algorithm.getCurveName());
    }

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void generate_rawPrivateBytes_hasExpectedLength(KeyAlgorithm algorithm) {
        GeneratedKeyPair result = factory.generate(algorithm);
        int expectedLength = switch (algorithm) {
            case ES256 -> 32;
            case ES384 -> 48;
            case EdDSA -> 32;
        };
        assertThat(result.rawPrivateBytes()).hasSize(expectedLength);
    }

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void generate_handle_privateKey_hasExpectedAlgorithm(KeyAlgorithm algorithm) {
        GeneratedKeyPair result = factory.generate(algorithm);
        PrivateKey pk = result.privateKeyHandle().value();
        if (algorithm == KeyAlgorithm.EdDSA) {
            assertThat(pk.getAlgorithm()).isEqualTo("Ed25519");
        } else {
            assertThat(pk.getAlgorithm()).isEqualTo("EC");
        }
    }

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void generate_eachCallProducesDifferentKey(KeyAlgorithm algorithm) {
        GeneratedKeyPair first = factory.generate(algorithm);
        GeneratedKeyPair second = factory.generate(algorithm);
        assertThat(first.rawPrivateBytes()).isNotEqualTo(second.rawPrivateBytes());
    }

    // --- fromBytes round-trip ---

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void fromBytes_roundTrip_reconstructsEquivalentPrivateKey(KeyAlgorithm algorithm) {
        GeneratedKeyPair generated = factory.generate(algorithm);
        byte[] rawBytes = generated.rawPrivateBytes().clone();

        PlaintextHandle<PrivateKey> reconstructed = factory.fromBytes(rawBytes, algorithm);

        if (algorithm == KeyAlgorithm.EdDSA) {
            assertThat(reconstructed.value().getAlgorithm()).isEqualTo("Ed25519");
        } else {
            ECPrivateKey original = (ECPrivateKey) generated.privateKeyHandle().value();
            ECPrivateKey restored = (ECPrivateKey) reconstructed.value();
            assertThat(restored.getS()).isEqualTo(original.getS());
        }
    }

    // --- PlaintextHandle zeroization ---

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void handle_close_zerosRawPrivateBytes(KeyAlgorithm algorithm) {
        GeneratedKeyPair result = factory.generate(algorithm);
        byte[] rawBytes = result.rawPrivateBytes();
        // Sanity: bytes are not already all zeros
        boolean notAllZero = false;
        for (byte b : rawBytes) {
            if (b != 0) { notAllZero = true; break; }
        }
        assertThat(notAllZero).as("raw bytes must not be all-zero before close").isTrue();

        result.privateKeyHandle().close();

        byte[] zeroed = new byte[rawBytes.length];
        assertThat(rawBytes)
                .as("raw bytes must be zeroed after handle.close()")
                .isEqualTo(zeroed);
    }

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void handle_closeIsIdempotent_secondCloseIsNoOp(KeyAlgorithm algorithm) {
        GeneratedKeyPair result = factory.generate(algorithm);
        result.privateKeyHandle().close();
        // second close must not throw
        result.privateKeyHandle().close();
    }

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void handle_toString_isRedacted(KeyAlgorithm algorithm) {
        GeneratedKeyPair result = factory.generate(algorithm);
        assertThat(result.privateKeyHandle().toString()).isEqualTo("PlaintextHandle[REDACTED]");
    }
}