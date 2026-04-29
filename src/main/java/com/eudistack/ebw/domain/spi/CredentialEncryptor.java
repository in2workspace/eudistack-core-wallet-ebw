package com.eudistack.ebw.domain.spi;

public interface CredentialEncryptor {

    String encrypt(String plaintext);

    String decrypt(String ciphertext);
}
