package com.eudistack.ebw.keymanager.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link SignHolderKeyCommand} invariants and defensive-copy contract.
 *
 * <p>Covers EUDISTACK-407 NFR-SEC-03.</p>
 */
class SignHolderKeyCommandTest {

    private static final HolderKeyId KEY_ID = HolderKeyId.generate();
    private static final byte[] INPUT = new byte[]{1, 2, 3, 4};

    private SignHolderKeyCommand validCommand(byte[] input) {
        return new SignHolderKeyCommand(
                KEY_ID, "tenant-a", "holder-b",
                SigningType.KB_JWT, SignaturePurpose.PRESENTATION, ConsumerOrigin.SYSTEM,
                input);
    }

    // --- compact constructor validations ---

    @Test
    void constructor_nullKeyId_throws() {
        assertThatThrownBy(() -> new SignHolderKeyCommand(
                null, "tenant", "holder",
                SigningType.KB_JWT, SignaturePurpose.PRESENTATION, ConsumerOrigin.SYSTEM,
                INPUT))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("keyId");
    }

    @Test
    void constructor_blankTenantId_throws() {
        assertThatThrownBy(() -> new SignHolderKeyCommand(
                KEY_ID, "  ", "holder",
                SigningType.KB_JWT, SignaturePurpose.PRESENTATION, ConsumerOrigin.SYSTEM,
                INPUT))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructor_blankHolderId_throws() {
        assertThatThrownBy(() -> new SignHolderKeyCommand(
                KEY_ID, "tenant", "",
                SigningType.KB_JWT, SignaturePurpose.PRESENTATION, ConsumerOrigin.SYSTEM,
                INPUT))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructor_nullSigningType_throws() {
        assertThatThrownBy(() -> new SignHolderKeyCommand(
                KEY_ID, "tenant", "holder",
                null, SignaturePurpose.PRESENTATION, ConsumerOrigin.SYSTEM,
                INPUT))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("signingType");
    }

    @Test
    void constructor_nullPurpose_throws() {
        assertThatThrownBy(() -> new SignHolderKeyCommand(
                KEY_ID, "tenant", "holder",
                SigningType.KB_JWT, null, ConsumerOrigin.SYSTEM,
                INPUT))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("purpose");
    }

    @Test
    void constructor_nullOrigin_throws() {
        assertThatThrownBy(() -> new SignHolderKeyCommand(
                KEY_ID, "tenant", "holder",
                SigningType.KB_JWT, SignaturePurpose.PRESENTATION, null,
                INPUT))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("origin");
    }

    @Test
    void constructor_emptySigningInput_throws() {
        assertThatThrownBy(() -> new SignHolderKeyCommand(
                KEY_ID, "tenant", "holder",
                SigningType.KB_JWT, SignaturePurpose.PRESENTATION, ConsumerOrigin.SYSTEM,
                new byte[0]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("signingInput");
    }

    // --- defensive copy ---

    @Test
    void signingInput_mutatingCallerArray_doesNotAffectCommand() {
        // Given
        byte[] original = new byte[]{10, 20, 30};
        SignHolderKeyCommand cmd = validCommand(original);

        // When — mutate caller's array after construction
        original[0] = 99;

        // Then — command still has original value
        assertThat(cmd.signingInput()[0]).isEqualTo((byte) 10);
    }

    @Test
    void signingInput_mutatingReturnedArray_doesNotAffectCommand() {
        // Given
        SignHolderKeyCommand cmd = validCommand(new byte[]{10, 20, 30});

        // When — mutate returned array
        byte[] returned = cmd.signingInput();
        returned[0] = 99;

        // Then — second call still returns original value
        assertThat(cmd.signingInput()[0]).isEqualTo((byte) 10);
    }

    // --- toString redaction ---

    @Test
    void toString_doesNotContainSigningInputBytes() {
        SignHolderKeyCommand cmd = validCommand(INPUT);
        String str = cmd.toString();

        assertThat(str)
                .contains("REDACTED")
                .doesNotContain("1, 2, 3, 4")
                .contains("keyId=")
                .contains("tenantId=");
    }
}
