package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.AuthRejectionReason;
import org.slf4j.Logger;

/** Logs a rejection with its fixed reason; the library detail only at DEBUG, truncated. */
final class AuthRejectionLog {

    private static final int MAX_DETAIL_LENGTH = 200;

    private AuthRejectionLog() {}

    static void log(Logger log, String what, AuthRejectionReason reason) {
        if (log.isInfoEnabled()) {
            log.info("{} rejected: {}", what, reason.code());
        }
    }

    /** The WebAuthn library message, only at DEBUG and truncated. */
    static void detail(Logger log, String what, Throwable cause) {
        if (log.isDebugEnabled()) {
            var detail = String.valueOf(cause.getMessage());
            log.debug("{} rejection detail: {}", what,
                    detail.length() > MAX_DETAIL_LENGTH ? detail.substring(0, MAX_DETAIL_LENGTH) : detail);
        }
    }
}
