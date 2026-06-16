package com.eudistack.ebw.keymanager.infrastructure.adapter.service;

import com.eudistack.ebw.keymanager.application.GenerateHolderKeyUseCase;
import com.eudistack.ebw.keymanager.application.SignHolderKeyUseCase;
import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto.PrepareSignRequest;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto.SubmitSignedAssertionRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * No-regression tests ensuring {@link DbKeyManagerService} continues to implement
 * {@link KeyManagerPort} correctly after the EUDISTACK-533 R-1 workaround added
 * {@code prepareSign} and {@code submitSignedAssertion} as default methods.
 *
 * <p>Spec: EUDISTACK-533 AC-06.</p>
 */
class DbKeyManagerServiceNoRegressionTest {

    private DbKeyManagerService service;

    @BeforeEach
    void setUp() {
        service = new DbKeyManagerService(
                mock(GenerateHolderKeyUseCase.class),
                mock(SignHolderKeyUseCase.class));
    }

    // --- AC-06: DbKeyManagerService still satisfies KeyManagerPort ---

    @Test
    void dbKeyManagerService_implementsKeyManagerPort() {
        assertThat(service).isInstanceOf(KeyManagerPort.class);
    }

    // --- Default method inheritance: prepareSign → UnsupportedOperationException ---

    @Test
    void prepareSign_inheritsDefaultMethodAndReturnsUnsupportedOperationException() {
        PrepareSignRequest request = new PrepareSignRequest("cred-1", "challenge", "dc+sd-jwt");

        StepVerifier.create(service.prepareSign(request))
                .expectErrorMatches(ex -> ex instanceof UnsupportedOperationException
                        && ex.getMessage().contains("prepareSign"))
                .verify();
    }

    // --- Default method inheritance: submitSignedAssertion → UnsupportedOperationException ---

    @Test
    void submitSignedAssertion_inheritsDefaultMethodAndReturnsUnsupportedOperationException() {
        SubmitSignedAssertionRequest request = new SubmitSignedAssertionRequest("cred-1", "sig", "corr-id");

        StepVerifier.create(service.submitSignedAssertion(request))
                .expectErrorMatches(ex -> ex instanceof UnsupportedOperationException
                        && ex.getMessage().contains("submitSignedAssertion"))
                .verify();
    }
}
