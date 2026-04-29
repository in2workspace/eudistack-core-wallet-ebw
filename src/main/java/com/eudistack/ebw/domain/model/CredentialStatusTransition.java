package com.eudistack.ebw.domain.model;

import com.eudistack.ebw.domain.model.exception.InvalidTransitionException;

import java.util.Map;
import java.util.Set;

public final class CredentialStatusTransition {

    private static final Map<CredentialStatus, Set<CredentialStatus>> ALLOWED = Map.of(
            CredentialStatus.VALID, Set.of(CredentialStatus.REVOKED, CredentialStatus.EXPIRED, CredentialStatus.SUSPENDED),
            CredentialStatus.SUSPENDED, Set.of(CredentialStatus.VALID),
            CredentialStatus.REVOKED, Set.of(),
            CredentialStatus.EXPIRED, Set.of()
    );

    private CredentialStatusTransition() {}

    public static void validate(CredentialStatus from, CredentialStatus to) {
        if (from == to) return;
        var allowed = ALLOWED.getOrDefault(from, Set.of());
        if (!allowed.contains(to)) {
            throw new InvalidTransitionException(from.name(), to.name());
        }
    }
}
