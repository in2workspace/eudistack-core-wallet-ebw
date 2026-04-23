package com.eudistack.ebw.domain.model.exception;

public class UserNotFoundException extends RuntimeException {

    public UserNotFoundException() {
        super("Email not registered. Please sign up first.");
    }
}
