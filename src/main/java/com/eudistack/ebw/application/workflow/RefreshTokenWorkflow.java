package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.AuthTokenPair;
import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuthTokenService;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class RefreshTokenWorkflow {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenWorkflow.class);

    private final AuthTokenService authTokenService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final WalletUserRepository userRepository;
    private final HashProvider hashProvider;

    public RefreshTokenWorkflow(AuthTokenService authTokenService,
                                RefreshTokenRepository refreshTokenRepository,
                                WalletUserRepository userRepository,
                                HashProvider hashProvider) {
        this.authTokenService = authTokenService;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.hashProvider = hashProvider;
    }

    public Mono<AuthTokenPair> refreshToken(String rawToken) {
        var tokenHash = hashProvider.sha256(rawToken);
        return refreshTokenRepository.findByTokenHash(tokenHash)
                .switchIfEmpty(Mono.error(new InvalidTokenException()))
                .flatMap(existing -> userRepository.findById(existing.getUserId())
                        .switchIfEmpty(Mono.error(new InvalidTokenException()))
                )
                .flatMap(user -> authTokenService.rotateRefreshToken(rawToken, user));
    }
}
