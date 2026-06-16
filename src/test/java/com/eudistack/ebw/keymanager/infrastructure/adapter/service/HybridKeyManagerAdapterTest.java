package com.eudistack.ebw.keymanager.infrastructure.adapter.service;

import com.eudistack.ebw.keymanager.domain.exception.UnsupportedCredentialFormatException;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto.PrepareSignRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

/**
 * Unit tests for {@link HybridKeyManagerAdapter} format allow-list validation.
 *
 * <p>Spec: EUDISTACK-533 AC-05, ES-01.</p>
 */
class HybridKeyManagerAdapterTest {

    private HybridKeyManagerAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new HybridKeyManagerAdapter();
    }

    // --- AC-05 / ES-01: unsupported formats are rejected at prepareSign time ---

    @Test
    void prepareSign_givenUnsupportedFormat_jwt_vc_json_ld_thenUnsupportedCredentialFormatException() {
        PrepareSignRequest request = new PrepareSignRequest("cred-1", "challenge-abc", "jwt_vc_json-ld");

        StepVerifier.create(adapter.prepareSign(request))
                .expectErrorMatches(ex -> ex instanceof UnsupportedCredentialFormatException
                        && ex.getMessage().contains("jwt_vc_json-ld"))
                .verify();
    }

    @Test
    void prepareSign_givenUnsupportedFormat_mdoc_thenUnsupportedCredentialFormatException() {
        PrepareSignRequest request = new PrepareSignRequest("cred-1", "challenge-abc", "mso_mdoc");

        StepVerifier.create(adapter.prepareSign(request))
                .expectErrorMatches(ex -> ex instanceof UnsupportedCredentialFormatException)
                .verify();
    }

    @Test
    void prepareSign_givenUnsupportedFormat_blank_thenUnsupportedCredentialFormatException() {
        PrepareSignRequest request = new PrepareSignRequest("cred-1", "challenge-abc", "application/vc");

        StepVerifier.create(adapter.prepareSign(request))
                .expectErrorMatches(ex -> ex instanceof UnsupportedCredentialFormatException)
                .verify();
    }

    // --- AC-05: supported formats pass allow-list and reach the stub ---

    @Test
    void prepareSign_givenSupportedFormat_dcSdJwt_thenPassesAllowList() {
        PrepareSignRequest request = new PrepareSignRequest("cred-1", "challenge-abc", "dc+sd-jwt");

        // The stub throws UnsupportedOperationException (TODO US-04), NOT UnsupportedCredentialFormatException.
        // This confirms format validation passed.
        StepVerifier.create(adapter.prepareSign(request))
                .expectErrorMatches(ex -> ex instanceof UnsupportedOperationException
                        && !(ex instanceof UnsupportedCredentialFormatException))
                .verify();
    }

    @Test
    void prepareSign_givenSupportedFormat_jwtVcJson_thenPassesAllowList() {
        PrepareSignRequest request = new PrepareSignRequest("cred-1", "challenge-abc", "jwt_vc_json");

        StepVerifier.create(adapter.prepareSign(request))
                .expectErrorMatches(ex -> ex instanceof UnsupportedOperationException
                        && !(ex instanceof UnsupportedCredentialFormatException))
                .verify();
    }

    // --- AC-06: generateHolderKey is not applicable for the hybrid adapter ---

    @Test
    void generateHolderKey_alwaysThrowsUnsupportedOperationException() {
        StepVerifier.create(adapter.generateHolderKey(null))
                .expectError(UnsupportedOperationException.class)
                .verify();
    }

    // --- signWithHolderKey not applicable for hybrid (AC-03 / US-04) ---

    @Test
    void signWithHolderKey_alwaysThrowsUnsupportedOperationException() {
        StepVerifier.create(adapter.signWithHolderKey(null))
                .expectError(UnsupportedOperationException.class)
                .verify();
    }
}
