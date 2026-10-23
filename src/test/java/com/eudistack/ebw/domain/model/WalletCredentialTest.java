package com.eudistack.ebw.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** Visibility of an attestation with passkey custody (EUD-11 FR-14, AC-04, AC-05, AC-10, AC-11). */
class WalletCredentialTest {

    private static final UUID SESSION_PASSKEY = UUID.randomUUID();

    private static WalletCredential credential(boolean bound, UUID passkeyId) {
        return WalletCredential.create(UUID.randomUUID(), "raw", CredentialFormat.DC_SD_JWT, "cfg", "kid", "Type",
                null, "iss", null, Instant.now(), null, Map.of(), null, bound, passkeyId);
    }

    @Test
    void isVisibleToPasskey_unbound_visibleFromAnyPasskey() {
        assertThat(credential(false, UUID.randomUUID()).isVisibleToPasskey(SESSION_PASSKEY)).isTrue();
    }

    @Test
    void isVisibleToPasskey_boundToTheSessionPasskey_visible() {
        assertThat(credential(true, SESSION_PASSKEY).isVisibleToPasskey(SESSION_PASSKEY)).isTrue();
    }

    @Test
    void isVisibleToPasskey_boundToAnotherPasskey_hidden() {
        assertThat(credential(true, UUID.randomUUID()).isVisibleToPasskey(SESSION_PASSKEY)).isFalse();
    }

    @Test
    void isVisibleToPasskey_boundWithoutPasskey_hidden() {
        assertThat(credential(true, null).isVisibleToPasskey(SESSION_PASSKEY)).isFalse();
    }

    @Test
    void create_unbound_dropsThePasskey() {
        assertThat(credential(false, SESSION_PASSKEY).getPasskeyId()).isNull();
    }
}
