package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.exception.UnsupportedSigningTypeException;
import com.eudistack.ebw.keymanager.domain.model.SigningType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link SignerSelector} (AC-03).
 */
class SignerSelectorTest {

    private JwsSigner kbJwtSigner;
    private JwsSigner vpEnvelopeSigner;
    private SignerSelector selector;

    @BeforeEach
    void setUp() {
        kbJwtSigner = mock(JwsSigner.class);
        vpEnvelopeSigner = mock(JwsSigner.class);
        selector = new SignerSelector(Map.of(
                SigningType.KB_JWT, kbJwtSigner,
                SigningType.VP_ENVELOPE, vpEnvelopeSigner
        ));
    }

    @Test
    void select_kbJwt_returnsKbJwtSigner() {
        assertThat(selector.select(SigningType.KB_JWT)).isSameAs(kbJwtSigner);
    }

    @Test
    void select_vpEnvelope_returnsVpEnvelopeSigner() {
        assertThat(selector.select(SigningType.VP_ENVELOPE)).isSameAs(vpEnvelopeSigner);
    }

    @Test
    void select_nullType_throwsNullPointer() {
        assertThatThrownBy(() -> selector.select(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void select_unregisteredType_throwsUnsupportedSigningTypeException() {
        // Simulate a registry that only has KB_JWT
        SignerSelector partialSelector = new SignerSelector(Map.of(SigningType.KB_JWT, kbJwtSigner));

        assertThatThrownBy(() -> partialSelector.select(SigningType.VP_ENVELOPE))
                .isInstanceOf(UnsupportedSigningTypeException.class)
                .hasMessageContaining("VP_ENVELOPE");
    }

    @Test
    void constructor_emptyRegistry_throws() {
        assertThatThrownBy(() -> new SignerSelector(Map.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
