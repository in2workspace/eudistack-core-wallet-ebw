package com.eudistack.ebw.infrastructure.adapter.audit;

import jakarta.mail.AuthenticationFailedException;
import org.junit.jupiter.api.Test;
import org.springframework.mail.MailAuthenticationException;
import org.springframework.mail.MailParseException;
import org.springframework.mail.MailSendException;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ExternalFailureClassifierTest {

    @Test
    void reasonOf_smtpAuthenticationRejected_returnsAuthenticationRejected() {
        // Arrange & Act
        String reason = ExternalFailureClassifier.reasonOf(
                new MailAuthenticationException("bad credentials", new AuthenticationFailedException("535")));

        // Assert
        assertEquals("AuthenticationRejected", reason);
    }

    @Test
    void reasonOf_socketTimeoutWrappedByTheMailClient_returnsTimeout() {
        // Arrange & Act
        String reason = ExternalFailureClassifier.reasonOf(new MailSendException("failed", new SocketTimeoutException("read")));

        // Assert
        assertEquals("Timeout", reason);
    }

    @Test
    void reasonOf_connectionRefused_returnsUnreachable() {
        // Arrange & Act
        String reason = ExternalFailureClassifier.reasonOf(new MailSendException("failed", new ConnectException("refused")));

        // Assert
        assertEquals("Unreachable", reason);
    }

    @Test
    void reasonOf_unknownHost_returnsUnreachable() {
        // Arrange & Act
        String reason = ExternalFailureClassifier.reasonOf(new UnknownHostException("smtp.example.com"));

        // Assert
        assertEquals("Unreachable", reason);
    }

    @Test
    void reasonOf_unparsableMessage_returnsInvalidResponse() {
        // Arrange & Act
        String reason = ExternalFailureClassifier.reasonOf(new MailParseException("malformed"));

        // Assert
        assertEquals("InvalidResponse", reason);
    }

    @Test
    void reasonOf_unrecognisedError_returnsErrorResponse() {
        // Arrange & Act
        String reason = ExternalFailureClassifier.reasonOf(new MailSendException("relay denied"));

        // Assert
        assertEquals("ErrorResponse", reason);
    }
}
