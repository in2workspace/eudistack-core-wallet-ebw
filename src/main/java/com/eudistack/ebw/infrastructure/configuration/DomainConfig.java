package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.repository.*;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import com.eudistack.ebw.domain.service.OtpService;
import com.eudistack.ebw.domain.spi.*;
import com.eudistack.ebw.infrastructure.adapter.properties.JwtProperties;
import com.eudistack.ebw.infrastructure.adapter.properties.OtpProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DomainConfig {

    @Bean
    public OtpService otpService(EmailVerificationRepository verificationRepository,
                                 HashProvider hashProvider,
                                 SecureRandomGenerator randomGenerator,
                                 EmailSender emailSender,
                                 OtpProperties otpProperties) {
        return new OtpService(verificationRepository, hashProvider, randomGenerator, emailSender,
                otpProperties.length(), otpProperties.expiration(), otpProperties.maxAttempts());
    }

    @Bean
    public AuthTokenService authTokenService(TokenSigner tokenSigner,
                                             HashProvider hashProvider,
                                             SecureRandomGenerator randomGenerator,
                                             RefreshTokenRepository refreshTokenRepository,
                                             JwtProperties jwtProperties) {
        return new AuthTokenService(tokenSigner, hashProvider, randomGenerator, refreshTokenRepository,
                jwtProperties.accessTokenTtl(), jwtProperties.refreshTokenTtl(), jwtProperties.issuer());
    }

    @Bean
    public AuditService auditService(AuditLogRepository auditLogRepository) {
        return new AuditService(auditLogRepository);
    }
}
