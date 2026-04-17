package com.eudistack.ebw.domain.model.exception;

public class UnsupportedFormatException extends RuntimeException {

    public UnsupportedFormatException(String format) {
        super("Unsupported credential format: " + format);
    }
}
