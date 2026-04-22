package com.eudistack.ebw.infrastructure.adapter.crypto;

import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.UUID;

@Component
public class CsprngGenerator implements SecureRandomGenerator {

    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public String generateOtp(int length) {
        var sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(secureRandom.nextInt(10));
        }
        return sb.toString();
    }

    @Override
    public UUID generateUuid() {
        return UUID.randomUUID();
    }
}
