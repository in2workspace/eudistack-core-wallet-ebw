package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;

@Service
public class LogoutWorkflow {

    private final AuthTokenService authTokenService;
    private final AuditService auditService;

    public LogoutWorkflow(AuthTokenService authTokenService, AuditService auditService) {
        this.authTokenService = authTokenService;
        this.auditService = auditService;
    }

    public Mono<Void> logout(String rawRefreshToken) {
        return authTokenService.revokeAllByRefreshToken(rawRefreshToken)
                .flatMap(userId -> auditService.record(
                        "USER", userId, "LOGOUT", userId, Map.of("type", "global_logout")))
                .then();
    }
}
