package com.eudistack.ebw.domain.model.exception;

public class UserAlreadyRegisteredException extends RuntimeException {

    public UserAlreadyRegisteredException() {
        super("Email already registered. Please log in instead.");
    }
}
