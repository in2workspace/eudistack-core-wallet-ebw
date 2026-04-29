package com.eudistack.ebw.domain.model;

import com.eudistack.ebw.domain.model.exception.InvalidTransitionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CredentialStatusTransitionTest {

    @ParameterizedTest
    @CsvSource({
            "VALID, REVOKED",
            "VALID, EXPIRED",
            "VALID, SUSPENDED",
            "SUSPENDED, VALID"
    })
    void validTransitions_doNotThrow(CredentialStatus from, CredentialStatus to) {
        assertThatNoException().isThrownBy(() -> CredentialStatusTransition.validate(from, to));
    }

    @ParameterizedTest
    @CsvSource({
            "REVOKED, VALID",
            "REVOKED, SUSPENDED",
            "REVOKED, EXPIRED",
            "EXPIRED, VALID",
            "EXPIRED, SUSPENDED",
            "EXPIRED, REVOKED",
            "SUSPENDED, REVOKED",
            "SUSPENDED, EXPIRED"
    })
    void invalidTransitions_throwException(CredentialStatus from, CredentialStatus to) {
        assertThatThrownBy(() -> CredentialStatusTransition.validate(from, to))
                .isInstanceOf(InvalidTransitionException.class)
                .hasMessageContaining(from.name())
                .hasMessageContaining(to.name());
    }

    @Test
    void sameStatus_isNoOp() {
        for (var status : CredentialStatus.values()) {
            assertThatNoException().isThrownBy(() -> CredentialStatusTransition.validate(status, status));
        }
    }
}
