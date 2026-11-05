package com.eudistack.ebw.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CustodyModeTest {

    @Test
    void fromDbValue_knownValues_returnTheMode() {
        // Arrange
        // the two stored values

        // Act
        var server = CustodyMode.fromDbValue("server");
        var passkey = CustodyMode.fromDbValue("passkey");

        // Assert
        assertThat(server).isEqualTo(CustodyMode.SERVER);
        assertThat(passkey).isEqualTo(CustodyMode.PASSKEY);
    }

    @Test
    void fromDbValue_null_returnsNull() {
        // Arrange
        String stored = null;

        // Act
        var mode = CustodyMode.fromDbValue(stored);

        // Assert
        assertThat(mode).isNull();
    }

    @Test
    void fromDbValue_unknownValue_throwsIllegalArgumentException() {
        // Arrange
        var stored = "hsm";

        // Act + Assert
        assertThatThrownBy(() -> CustodyMode.fromDbValue(stored)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void getDbValue_eachMode_matchesTheCheckConstraint() {
        // Arrange
        // the CHECK of wallet_credential.custody_mode accepts server and passkey

        // Act + Assert
        assertThat(CustodyMode.SERVER.getDbValue()).isEqualTo("server");
        assertThat(CustodyMode.PASSKEY.getDbValue()).isEqualTo("passkey");
    }
}
