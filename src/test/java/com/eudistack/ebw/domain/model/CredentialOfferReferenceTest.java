package com.eudistack.ebw.domain.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link CredentialOfferReference} (ES-01). */
class CredentialOfferReferenceTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F3f2a",
            "openid-credential-offer://wallet?credential_offer_uri=https://issuer.example/offer/1",
            "OPENID-CREDENTIAL-OFFER://?foo=bar&credential_offer_uri=https%3A%2F%2Fi.example%2Fo"})
    void isValid_offerByReference_isAccepted(String offer) {
        assertThat(CredentialOfferReference.isValid(offer)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://issuer.example/offer/1",
            "openid-credential-offer://",
            "openid-credential-offer://?credential_offer_uri=",
            "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22x%22%7D",
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fi.example&credential_offer=%7B%7D",
            "openid-credential-offer://?credential_offer_uri=%ZZ",
            "openid-credential-offer://?credential_offer_uri=https://i.example/o#fragment",
            "openid-credential-offer://?credential_offer_uri=https://i.example/a b"})
    void isValid_otherValues_areRejected(String offer) {
        assertThat(CredentialOfferReference.isValid(offer)).isFalse();
    }

    @Test
    void isValid_longerThan2048_isRejected() {
        var prefix = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fi.example%2F";
        assertThat(CredentialOfferReference.isValid(prefix + "a".repeat(2048 - prefix.length()))).isTrue();
        assertThat(CredentialOfferReference.isValid(prefix + "a".repeat(2049 - prefix.length()))).isFalse();
    }
}
