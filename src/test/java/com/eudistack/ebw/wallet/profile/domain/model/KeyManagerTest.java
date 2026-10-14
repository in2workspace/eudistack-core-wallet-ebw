package com.eudistack.ebw.wallet.profile.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class KeyManagerTest {

    @Test
    void passkeyPrf_dbValue_isPasskeyPrf() {
        assertThat(KeyManager.PASSKEY_PRF.getDbValue()).isEqualTo("passkey-prf");
    }

    @Test
    void fromDbValue_passkeyPrf_resolvesToPasskeyPrf() {
        assertThat(KeyManager.fromDbValue("passkey-prf")).isEqualTo(KeyManager.PASSKEY_PRF);
    }

    @Test
    void fromDbValue_legacyHybrid_isRejected() {
        assertThatThrownBy(() -> KeyManager.fromDbValue("hybrid"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
