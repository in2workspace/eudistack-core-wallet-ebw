package com.eudistack.ebw.keymanager.domain.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CredentialFormatTest {

    @ParameterizedTest(name = "{0} → dbValue={1}")
    @CsvSource({
        "SD_JWT_VC, dc+sd-jwt",
        "VC_JWT,    jwt_vc_json"
    })
    void dbValue_matchesOid4vciFormatIdentifier(String enumName, String expectedDbValue) {
        CredentialFormat format = CredentialFormat.valueOf(enumName);
        assertThat(format.dbValue()).isEqualTo(expectedDbValue);
    }

    @ParameterizedTest(name = "fromDbValue({0}) → {1}")
    @CsvSource({
        "dc+sd-jwt,    SD_JWT_VC",
        "jwt_vc_json,  VC_JWT"
    })
    void fromDbValue_roundTrips(String dbValue, String expectedEnum) {
        CredentialFormat result = CredentialFormat.fromDbValue(dbValue);
        assertThat(result).isEqualTo(CredentialFormat.valueOf(expectedEnum));
    }

    @Test
    void fromDbValue_unknownValue_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> CredentialFormat.fromDbValue("unknown-format"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unknown-format");
    }

    @Test
    void fromDbValue_caseSensitive_rejectsWrongCase() {
        assertThatThrownBy(() -> CredentialFormat.fromDbValue("DC+SD-JWT"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void fromDbValue_null_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> CredentialFormat.fromDbValue(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void enum_hasExactlyTwoValues() {
        assertThat(CredentialFormat.values()).hasSize(2);
    }
}