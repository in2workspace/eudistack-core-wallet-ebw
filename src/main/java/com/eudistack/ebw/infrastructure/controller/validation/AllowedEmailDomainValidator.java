package com.eudistack.ebw.infrastructure.controller.validation;

import com.eudistack.ebw.infrastructure.adapter.properties.RegistrationProperties;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

public class AllowedEmailDomainValidator implements ConstraintValidator<AllowedEmailDomain, String> {

    private final Set<String> allowedDomains;
    private final boolean wildcardEnabled;

    public AllowedEmailDomainValidator(RegistrationProperties properties) {
        var lowercased = properties.allowedEmailDomains().stream()
                .map(d -> d.toLowerCase(Locale.ROOT))
                .collect(Collectors.toSet());
        this.wildcardEnabled = lowercased.contains("*");
        this.allowedDomains = lowercased;
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isBlank()) {
            return true; // delegate to @NotBlank
        }
        int atIndex = value.lastIndexOf('@');
        if (atIndex < 0) {
            return true; // delegate to @Email
        }
        if (wildcardEnabled) {
            return true;
        }
        String domain = value.substring(atIndex + 1).toLowerCase(Locale.ROOT);
        return allowedDomains.contains(domain);
    }
}
