package com.eudistack.ebw.domain.model.exception;

public class PayloadTooLargeException extends RuntimeException {

    public PayloadTooLargeException(long maxSize) {
        super("Request body exceeds maximum allowed size of " + maxSize + " bytes");
    }
}
