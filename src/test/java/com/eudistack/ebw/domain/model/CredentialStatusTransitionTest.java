package com.eudistack.ebw.domain.model;

import com.eudistack.ebw.domain.model.exception.InvalidTransitionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CredentialStatusTransitionTest {

    @ParameterizedTest
    @CsvSource({
            "VALID, REVOKED",
            "VALID, EXPIRED"
    })
    void validTransitions_doNotThrow(CredentialStatus from, CredentialStatus to) {
        assertThatNoException().isThrownBy(() -> CredentialStatusTransition.validate(from, to));
    }

    @ParameterizedTest
    @CsvSource({
            "REVOKED, VALID",
            "REVOKED, EXPIRED",
            "EXPIRED, VALID",
            "EXPIRED, REVOKED"
    })
    void invalidTransitions_throwException(CredentialStatus from, CredentialStatus to) {
        assertThatThrownBy(() -> CredentialStatusTransition.validate(from, to))
                .isInstanceOf(InvalidTransitionException.class)
                .hasMessageContaining(from.name())
                .hasMessageContaining(to.name());
    }

    @Test
    void statuses_areOnlyValidRevokedAndExpired() {
        // Arrange + Act
        var names = Arrays.stream(CredentialStatus.values()).map(Enum::name).toList();

        // Assert
        assertThat(names).containsExactlyInAnyOrder("VALID", "REVOKED", "EXPIRED");
    }

    @Test
    void sameStatus_isNoOp() {
        for (var status : CredentialStatus.values()) {
            assertThatNoException().isThrownBy(() -> CredentialStatusTransition.validate(status, status));
        }
    }
}
