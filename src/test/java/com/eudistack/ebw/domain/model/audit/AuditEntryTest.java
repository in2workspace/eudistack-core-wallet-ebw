package com.eudistack.ebw.domain.model.audit;

import com.eudistack.ebw.domain.model.exception.InvalidAuditEntryException;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuditEntryTest {

    private static final String RESOURCE = "external-system:smtp.example.com";

    @Test
    void success_withoutDetails_buildsEntryWithoutReasonFromTheWalletSource() {
        // Arrange & Act
        AuditEntry entry = AuditEntry.success(AuditEventType.EXTERNAL_SYSTEM_ACCESS, RESOURCE, null);

        // Assert
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertNull(entry.reason());
        assertEquals(AuditSource.WALLET_EBW, entry.source());
        assertEquals(Map.of(), entry.details());
    }

    @Test
    void forReason_reasonOfTheFailureVocabulary_derivesFailure() {
        // Arrange & Act
        AuditEntry entry = AuditEntry.forReason(AuditEventType.EXTERNAL_SYSTEM_ACCESS, RESOURCE, "Timeout", Map.of());

        // Assert
        assertEquals(AuditResult.FAILURE, entry.result());
    }

    @Test
    void forReason_reasonOfTheDeniedVocabulary_derivesDenied() {
        // Arrange & Act
        AuditEntry entry = AuditEntry.forReason(
                AuditEventType.EXTERNAL_SYSTEM_ACCESS, RESOURCE, "AuthenticationRejected", Map.of());

        // Assert
        assertEquals(AuditResult.DENIED, entry.result());
    }

    @Test
    void forReason_reasonOutsideTheVocabulary_throwsInvalidAuditEntryException() {
        // Arrange & Act & Assert
        assertThrows(InvalidAuditEntryException.class,
                () -> AuditEntry.forReason(AuditEventType.EXTERNAL_SYSTEM_ACCESS, RESOURCE, "MailDeliveryFailed", Map.of()));
    }

    @Test
    void constructor_failureWithAReasonThatDeterminesDenied_throwsInvalidAuditEntryException() {
        // Arrange & Act & Assert
        assertThrows(InvalidAuditEntryException.class, () -> new AuditEntry(
                AuditEventType.EXTERNAL_SYSTEM_ACCESS, null, RESOURCE, AuditResult.FAILURE, "AuthenticationRejected", Map.of()));
    }

    @Test
    void constructor_successWithReason_throwsInvalidAuditEntryException() {
        // Arrange & Act & Assert
        assertThrows(InvalidAuditEntryException.class, () -> new AuditEntry(
                AuditEventType.EXTERNAL_SYSTEM_ACCESS, null, RESOURCE, AuditResult.SUCCESS, "Timeout", Map.of()));
    }

    @Test
    void constructor_blankResource_throwsInvalidAuditEntryException() {
        // Arrange & Act & Assert
        assertThrows(InvalidAuditEntryException.class,
                () -> AuditEntry.success(AuditEventType.EXTERNAL_SYSTEM_ACCESS, " ", Map.of()));
    }

    @Test
    void success_withNullDetail_omitsIt() {
        // Arrange
        Map<String, Object> details = new HashMap<>();
        details.put("kept", "value");
        details.put("absent", null);

        // Act
        AuditEntry entry = AuditEntry.success(AuditEventType.EXTERNAL_SYSTEM_ACCESS, RESOURCE, details);

        // Assert
        assertFalse(entry.details().containsKey("absent"));
        assertEquals("value", entry.details().get("kept"));
    }
}
