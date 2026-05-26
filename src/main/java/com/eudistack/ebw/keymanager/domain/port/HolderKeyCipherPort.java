package com.eudistack.ebw.keymanager.domain.port;

public interface HolderKeyCipherPort {

    byte[] encrypt(byte[] plaintext, String tenantId);

    byte[] decrypt(byte[] ciphertext, String tenantId);

    boolean isOperational();
}