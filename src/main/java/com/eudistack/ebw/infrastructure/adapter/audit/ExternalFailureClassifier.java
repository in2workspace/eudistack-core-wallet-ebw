package com.eudistack.ebw.infrastructure.adapter.audit;

import jakarta.mail.AuthenticationFailedException;
import org.springframework.mail.MailAuthenticationException;
import org.springframework.mail.MailParseException;

import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Optional;
import java.util.concurrent.TimeoutException;

/**
 * Maps the error of a call to a third party to the {@code ExternalSystemAccess} reason of the catalogue.
 * The reason is read from the first cause that identifies the failure, since the clients wrap the
 * network error they hit; anything unrecognised is an error response from the system.
 */
public final class ExternalFailureClassifier {

    public static final String AUTHENTICATION_REJECTED = "AuthenticationRejected";
    public static final String ERROR_RESPONSE = "ErrorResponse";
    public static final String INVALID_RESPONSE = "InvalidResponse";
    public static final String TIMEOUT = "Timeout";
    public static final String UNREACHABLE = "Unreachable";

    private static final int MAX_CAUSE_DEPTH = 10;

    private ExternalFailureClassifier() {
    }

    public static String reasonOf(Throwable error) {
        Throwable current = error;
        for (int depth = 0; current != null && depth < MAX_CAUSE_DEPTH; depth++) {
            Optional<String> reason = reasonOfSingle(current);
            if (reason.isPresent()) {
                return reason.get();
            }
            current = current.getCause();
        }
        return ERROR_RESPONSE;
    }

    private static Optional<String> reasonOfSingle(Throwable error) {
        if (error instanceof MailAuthenticationException || error instanceof AuthenticationFailedException) {
            return Optional.of(AUTHENTICATION_REJECTED);
        }
        if (error instanceof SocketTimeoutException || error instanceof TimeoutException) {
            return Optional.of(TIMEOUT);
        }
        if (error instanceof ConnectException || error instanceof UnknownHostException
                || error instanceof NoRouteToHostException) {
            return Optional.of(UNREACHABLE);
        }
        if (error instanceof MailParseException) {
            return Optional.of(INVALID_RESPONSE);
        }
        return Optional.empty();
    }
}
