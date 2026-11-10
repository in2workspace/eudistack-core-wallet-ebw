package com.eudistack.ebw.keymanager.infrastructure.adapter.service;

import com.eudistack.ebw.keymanager.application.GenerateHolderKeyUseCase;
import com.eudistack.ebw.keymanager.application.SignHolderKeyUseCase;
import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/** {@link DbKeyManagerService} keeps satisfying {@link KeyManagerPort}. */
class DbKeyManagerServiceNoRegressionTest {

    @Test
    void dbKeyManagerService_implementsKeyManagerPort() {
        // Arrange
        var service = new DbKeyManagerService(mock(GenerateHolderKeyUseCase.class), mock(SignHolderKeyUseCase.class));

        // Act
        boolean implementsPort = service instanceof KeyManagerPort;

        // Assert
        assertThat(implementsPort).isTrue();
    }
}
