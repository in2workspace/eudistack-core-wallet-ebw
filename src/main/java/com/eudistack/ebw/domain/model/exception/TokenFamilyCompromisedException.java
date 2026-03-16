package com.eudistack.ebw.domain.model.exception;

public class TokenFamilyCompromisedException extends RuntimeException {

    public TokenFamilyCompromisedException() {
        super("Token family compromised — all sessions revoked");
    }
}
