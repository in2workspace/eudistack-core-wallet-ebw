package com.eudistack.ebw.keymanager.infrastructure.adapter.service;

import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.model.ConsumerOrigin;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.GenerateHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.SignaturePurpose;
import com.eudistack.ebw.keymanager.domain.model.SigningType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.util.List;

/** With passkey custody the Wallet Unit Service holds no key: generating and signing do not belong to the mode. */
class PasskeyPrfKeyManagerAdapterTest {

    private PasskeyPrfKeyManagerAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new PasskeyPrfKeyManagerAdapter();
    }

    @Test
    void generateHolderKey_anyCommand_failsWithUnsupportedCustodyMode() {
        // Arrange
        var command = new GenerateHolderKeyCommand("cgcom", "holder-1", "cred-1", CredentialFormat.SD_JWT_VC,
                List.of("ES256"), "https://issuer.example", null);

        // Act
        var result = adapter.generateHolderKey(command);

        // Assert
        StepVerifier.create(result).expectError(TenantWalletProfileUnsupportedException.class).verify();
    }

    @Test
    void signWithHolderKey_anyCommand_failsWithUnsupportedCustodyMode() {
        // Arrange
        var command = new SignHolderKeyCommand(HolderKeyId.generate(), "cgcom", "holder-1", SigningType.KB_JWT,
                SignaturePurpose.PRESENTATION, ConsumerOrigin.SYSTEM, new byte[] {1});

        // Act
        var result = adapter.signWithHolderKey(command);

        // Assert
        StepVerifier.create(result).expectError(TenantWalletProfileUnsupportedException.class).verify();
    }
}
