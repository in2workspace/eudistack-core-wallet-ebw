package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.repository.AuditLogRepository;
import com.eudistack.ebw.domain.repository.EmailVerificationRepository;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import com.eudistack.ebw.domain.service.CredentialService;
import com.eudistack.ebw.domain.service.OtpService;
import com.eudistack.ebw.domain.spi.EmailSender;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.infrastructure.adapter.properties.JwtProperties;
import com.eudistack.ebw.infrastructure.adapter.properties.OtpProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
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

    @Bean
    public CredentialService credentialService(HashProvider hashProvider, ObjectMapper objectMapper) {
        return new CredentialService(hashProvider, objectMapper);
    }
}
