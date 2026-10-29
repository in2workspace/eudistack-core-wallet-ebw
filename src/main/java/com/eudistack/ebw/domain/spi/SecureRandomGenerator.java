package com.eudistack.ebw.domain.spi;

import java.util.UUID;

public interface SecureRandomGenerator {

    String generateOtp(int length);

    UUID generateUuid();

    /** Cryptographically secure random bytes. */
    byte[] generateBytes(int length);
}
