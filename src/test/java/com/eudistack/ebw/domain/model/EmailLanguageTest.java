package com.eudistack.ebw.domain.model;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link EmailLanguage}: the languages of the Wallet App, read from {@code Accept-Language}. */
class EmailLanguageTest {

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "es|es",
            "ca-ES|ca",
            "en-GB,en;q=0.9|en",
            "fr-FR,ca;q=0.8,es;q=0.5|ca",
            "de, es;q=0.1|es"})
    void fromAcceptLanguage_supportedLanguage_isThePreferredOne(String header, String expected) {
        assertThat(EmailLanguage.fromAcceptLanguage(header)).contains(expected);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"fr-FR", "de;q=0.9", "not a ;; header"})
    void fromAcceptLanguage_noSupportedLanguage_isEmpty(String header) {
        assertThat(EmailLanguage.fromAcceptLanguage(header)).isEmpty();
    }

    @ParameterizedTest
    @CsvSource({"ES,es", " ca ,ca", "en,en"})
    void parse_supportedValue_isNormalized(String value, String expected) {
        assertThat(EmailLanguage.parse(value)).contains(expected);
    }

    @ParameterizedTest
    @ValueSource(strings = {"fr", "es-ES", ""})
    void parse_otherValue_isEmpty(String value) {
        assertThat(EmailLanguage.parse(value)).isEmpty();
    }
}
