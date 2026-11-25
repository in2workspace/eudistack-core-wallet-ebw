package com.eudistack.ebw.domain.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link WalletInstance}: the name rules of EUD-15 FR-04 and FR-12, and a new instance. */
class WalletInstanceTest {

    @Test
    void normalizeDisplayName_surroundingBlanks_areTrimmed() {
        assertThat(WalletInstance.normalizeDisplayName("  iPhone · Safari  ")).isEqualTo("iPhone · Safari");
    }

    @Test
    void normalizeDisplayName_fiftyCharacters_isValid() {
        var name = "a".repeat(50);
        assertThat(WalletInstance.normalizeDisplayName(name)).isEqualTo(name);
    }

    @Test
    void normalizeDisplayName_fiftyEmojis_countsCharactersNotUtf16Units() {
        var name = "📱".repeat(50);
        assertThat(WalletInstance.normalizeDisplayName(name)).isEqualTo(name);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "line\nbreak", "tab\tname"})
    void normalizeDisplayName_emptyOrWithControlCharacters_isInvalid(String name) {
        assertThat(WalletInstance.normalizeDisplayName(name)).isNull();
    }

    @Test
    void normalizeDisplayName_fiftyOneCharacters_isInvalid() {
        assertThat(WalletInstance.normalizeDisplayName("a".repeat(51))).isNull();
    }

    @Test
    void normalizeDisplayName_null_isInvalid() {
        assertThat(WalletInstance.normalizeDisplayName(null)).isNull();
    }

    @Test
    void register_newInstance_isActiveWithThePasskeyOfTheSessionAndNoRevocation() {
        // FR-03: active, with its name, type, the passkey of the session and the date; no keys (AD-1)
        var userId = UUID.randomUUID();
        var passkeyId = UUID.randomUUID();

        var instance = WalletInstance.register(userId, " Mac · Chrome ", WalletInstance.DeviceType.DESKTOP, passkeyId);

        assertThat(instance.isActive()).isTrue();
        assertThat(instance.userId()).isEqualTo(userId);
        assertThat(instance.displayName()).isEqualTo("Mac · Chrome");
        assertThat(instance.registeredPasskeyId()).isEqualTo(passkeyId);
        assertThat(instance.createdAt()).isNotNull();
        assertThat(instance.revokedAt()).isNull();
        assertThat(instance.revokedBy()).isNull();
    }
}
