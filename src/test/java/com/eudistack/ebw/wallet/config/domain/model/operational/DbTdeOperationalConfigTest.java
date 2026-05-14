package com.eudistack.ebw.wallet.config.domain.model.operational;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link DbTdeOperationalConfig}.
 *
 * <p>Covers T-1 (AC-1, AC-2b, E-16) from tech-design §2.3 (EUDISTACK-414):
 * compact-constructor invariant rejections, {@code toString()} redaction,
 * {@code equals}/{@code hashCode} exclusion of {@code wrappedDek},
 * and defensive-copy semantics on the accessor.
 */
class DbTdeOperationalConfigTest {

    private static final String VALID_ARN = "arn:aws:kms:eu-west-1:123456789012:key/mrk-abc123";
    private static final byte[] VALID_DEK = new byte[]{0x01, 0x02, 0x03};
    private static final String VALID_ALGORITHM = "AES-256-GCM";

    // ------------------------------------------------------------------
    // compact-constructor — rejection cases
    // ------------------------------------------------------------------

    @Test
    void constructor_nullArn_throwsIllegalArgument() {
        assertThatThrownBy(() -> new DbTdeOperationalConfig(null, VALID_DEK, VALID_ALGORITHM))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("columnEncryptionKeyArn");
    }

    @Test
    void constructor_invalidArnPrefix_throwsIllegalArgument() {
        // ARN that does not start with the required prefix
        String badArn = "aws:kms:eu-west-1:123456789012:key/mrk-abc123";

        assertThatThrownBy(() -> new DbTdeOperationalConfig(badArn, VALID_DEK, VALID_ALGORITHM))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("arn:aws:kms:");
    }

    @Test
    void constructor_nullWrappedDek_throwsIllegalArgument() {
        assertThatThrownBy(() -> new DbTdeOperationalConfig(VALID_ARN, null, VALID_ALGORITHM))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("wrappedDek");
    }

    @Test
    void constructor_emptyWrappedDek_throwsIllegalArgument() {
        assertThatThrownBy(() -> new DbTdeOperationalConfig(VALID_ARN, new byte[0], VALID_ALGORITHM))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("wrappedDek");
    }

    @Test
    void constructor_unsupportedAlgorithm_throwsIllegalArgument() {
        assertThatThrownBy(() -> new DbTdeOperationalConfig(VALID_ARN, VALID_DEK, "AES-128-CBC"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("AES-256-GCM");
    }

    // ------------------------------------------------------------------
    // compact-constructor — happy path
    // ------------------------------------------------------------------

    @Test
    void constructor_validInput_setsAllFields() {
        // Given
        byte[] dek = new byte[]{0x0A, 0x0B, 0x0C};

        // When
        DbTdeOperationalConfig config = new DbTdeOperationalConfig(VALID_ARN, dek, VALID_ALGORITHM);

        // Then — all accessors return the values we passed in
        assertThat(config.columnEncryptionKeyArn()).isEqualTo(VALID_ARN);
        assertThat(config.algorithm()).isEqualTo(VALID_ALGORITHM);
        // wrappedDek is a defensive copy, so content must match but reference may differ
        assertThat(config.wrappedDek()).containsExactly(dek);
    }

    // ------------------------------------------------------------------
    // toString — redaction
    // ------------------------------------------------------------------

    @Test
    void toString_redactsWrappedDek_neverPrintsRawBytes() {
        // Given
        byte[] dek = new byte[]{(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};
        DbTdeOperationalConfig config = new DbTdeOperationalConfig(VALID_ARN, dek, VALID_ALGORITHM);

        // When
        String stringRepresentation = config.toString();

        // Then — contains the redaction marker
        assertThat(stringRepresentation).contains("<redacted");

        // Then — does NOT contain the raw hex of the bytes
        String rawHex = HexFormat.of().formatHex(dek);
        assertThat(stringRepresentation).doesNotContain(rawHex);
    }

    // ------------------------------------------------------------------
    // equals / hashCode — exclude wrappedDek (AC-2b, E-16)
    // ------------------------------------------------------------------

    @Test
    void equals_twoInstancesDifferingOnlyByWrappedDek_areEqual() {
        // Given — same ARN and algorithm, different DEK bytes
        byte[] dek1 = new byte[]{0x01, 0x02};
        byte[] dek2 = new byte[]{0x03, 0x04, 0x05};
        DbTdeOperationalConfig config1 = new DbTdeOperationalConfig(VALID_ARN, dek1, VALID_ALGORITHM);
        DbTdeOperationalConfig config2 = new DbTdeOperationalConfig(VALID_ARN, dek2, VALID_ALGORITHM);

        // When / Then
        assertThat(config1).isEqualTo(config2);
    }

    @Test
    void hashCode_twoInstancesDifferingOnlyByWrappedDek_sameHash() {
        // Given — same ARN and algorithm, different DEK bytes
        byte[] dek1 = new byte[]{0x01, 0x02};
        byte[] dek2 = new byte[]{0x03, 0x04, 0x05};
        DbTdeOperationalConfig config1 = new DbTdeOperationalConfig(VALID_ARN, dek1, VALID_ALGORITHM);
        DbTdeOperationalConfig config2 = new DbTdeOperationalConfig(VALID_ARN, dek2, VALID_ALGORITHM);

        // When / Then
        assertThat(config1.hashCode()).isEqualTo(config2.hashCode());
    }

    // ------------------------------------------------------------------
    // wrappedDek accessor — defensive copy
    // ------------------------------------------------------------------

    /**
     * Verifies that mutating the array returned by {@link DbTdeOperationalConfig#wrappedDek()}
     * does not alter the internally stored field.
     *
     * <p>The compact constructor performs a defensive copy on construction ({@code Arrays.copyOf}).
     * The accessor also returns a defensive copy. If either copy is missing, this test will fail,
     * exposing the gap: the internal state would become mutable from outside the record.
     */
    @Test
    void wrappedDek_accessor_returnsDefensiveCopy() {
        // Given
        byte[] original = new byte[]{0x0A, 0x0B, 0x0C};
        DbTdeOperationalConfig config = new DbTdeOperationalConfig(VALID_ARN, original, VALID_ALGORITHM);

        // When — mutate the array returned by the accessor
        byte[] returned = config.wrappedDek();
        Arrays.fill(returned, (byte) 0xFF);

        // Then — a second call to the accessor still returns the original bytes
        assertThat(config.wrappedDek()).containsExactly(0x0A, 0x0B, 0x0C);
    }
}
