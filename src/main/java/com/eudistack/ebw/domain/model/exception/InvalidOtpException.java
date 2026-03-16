package com.eudistack.ebw.domain.model.exception;

public class InvalidOtpException extends RuntimeException {

    public InvalidOtpException() {
        super("Invalid verification code");
    }
}
