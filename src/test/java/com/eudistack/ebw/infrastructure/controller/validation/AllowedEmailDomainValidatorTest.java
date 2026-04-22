package com.eudistack.ebw.infrastructure.controller.validation;

import com.eudistack.ebw.infrastructure.adapter.properties.RegistrationProperties;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AllowedEmailDomainValidatorTest {

    private AllowedEmailDomainValidator validator(List<String> domains) {
        return new AllowedEmailDomainValidator(new RegistrationProperties(domains));
    }

    @Test
    void null_isValid() {
        assertThat(validator(List.of("example.com")).isValid(null, null)).isTrue();
    }

    @Test
    void blank_isValid() {
        assertThat(validator(List.of("example.com")).isValid("  ", null)).isTrue();
    }

    @Test
    void noAtSign_isValid() {
        assertThat(validator(List.of("example.com")).isValid("notanemail", null)).isTrue();
    }

    @Test
    void emptyWhitelist_isInvalid() {
        assertThat(validator(List.of()).isValid("user@example.com", null)).isFalse();
    }

    @Test
    void wildcard_allowsAnyDomain() {
        assertThat(validator(List.of("*")).isValid("user@anything.org", null)).isTrue();
    }

    @Test
    void wildcardMixedWithOthers_allowsAnyDomain() {
        assertThat(validator(List.of("example.com", "*")).isValid("user@other.io", null)).isTrue();
    }

    @Test
    void matchedDomain_isValid() {
        assertThat(validator(List.of("example.com")).isValid("user@example.com", null)).isTrue();
    }

    @Test
    void caseInsensitiveEmail_isValid() {
        assertThat(validator(List.of("example.com")).isValid("USER@Example.COM", null)).isTrue();
    }

    @Test
    void caseInsensitiveWhitelist_isValid() {
        assertThat(validator(List.of("Example.COM")).isValid("user@example.com", null)).isTrue();
    }

    @Test
    void unmatchedDomain_isInvalid() {
        assertThat(validator(List.of("example.com")).isValid("user@evil.com", null)).isFalse();
    }

    @Test
    void multipleAllowedDomains_matchesCorrectOne() {
        var v = validator(List.of("acme.com", "contoso.com"));
        assertThat(v.isValid("user@acme.com", null)).isTrue();
        assertThat(v.isValid("user@contoso.com", null)).isTrue();
        assertThat(v.isValid("user@other.com", null)).isFalse();
    }

    @Test
    void multipleAtSigns_domainFromLastAt() {
        assertThat(validator(List.of("example.com")).isValid("a@b@example.com", null)).isTrue();
    }
}
