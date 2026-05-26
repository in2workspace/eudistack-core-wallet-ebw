package com.eudistack.ebw.keymanager.domain.exception;

public class KeyAccessDeniedException extends RuntimeException {

    public KeyAccessDeniedException() {
        super("Key access denied");
    }
}