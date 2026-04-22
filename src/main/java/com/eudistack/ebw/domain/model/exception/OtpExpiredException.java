package com.eudistack.ebw.domain.model.exception;

public class OtpExpiredException extends RuntimeException {

    public OtpExpiredException() {
        super("Verification code has expired");
    }
}
