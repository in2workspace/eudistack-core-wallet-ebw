package com.eudistack.ebw.keymanager.domain.exception;

/**
 * Thrown when a hybrid onboarding commit cannot proceed due to a state conflict.
 *
 * <p>Two conditions trigger this exception:
 * <ul>
 *   <li>No PRF-salt row exists for {@code (tenantId, holderId, credentialId)} — the
 *       onboarding init step (US-05 / EUDISTACK-537) was not executed for this
 *       credential before the commit was attempted.</li>
 *   <li>A wrapped key handle already exists for {@code (holderId, credentialId)} with
 *       different {@code wrapped_blob} content — a non-idempotent replay.</li>
 * </ul>
 *
 * <p>Maps to HTTP 409 in {@code HybridOnboardingExceptionHandler} (architecture.md §8.3
 * {@code idempotency_replay}).</p>
 *
 * <p>Spec: EUDISTACK-534 ES-02, ES-03; architecture.md §8.3.</p>
 */
public class OnboardingStateException extends RuntimeException {

    public OnboardingStateException(String reason) {
        super(reason);
    }
}