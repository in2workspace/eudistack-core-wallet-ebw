package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.CredentialFormat;
import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.CredentialStatusTransition;
import com.eudistack.ebw.domain.model.exception.MalformedCredentialException;
import com.eudistack.ebw.domain.model.exception.UnsupportedFormatException;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.nimbusds.jwt.SignedJWT;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.text.ParseException;
import java.time.Instant;
import java.util.Map;

public class CredentialService {

    private final HashProvider hashProvider;

    public CredentialService(HashProvider hashProvider) {
        this.hashProvider = hashProvider;
    }

    public record ParsedCredential(
            String issuer,
            String subject,
            Instant issuanceDate,
            Instant expirationDate,
            String credentialType,
            String vct
    ) {}

    public Mono<ParsedCredential> parseCredential(String raw, CredentialFormat format) {
        return Mono.fromCallable(() -> {
            try {
                return switch (format) {
                    case JWT_VC_JSON -> parseJwt(raw);
                    case DC_SD_JWT -> parseSdJwt(raw);
                };
            } catch (ParseException e) {
                throw new MalformedCredentialException(e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    public CredentialFormat validateFormat(String format) {
        try {
            return CredentialFormat.fromValue(format);
        } catch (IllegalArgumentException e) {
            throw new UnsupportedFormatException(format);
        }
    }

    public void validateStatusTransition(CredentialStatus from, CredentialStatus to) {
        CredentialStatusTransition.validate(from, to);
    }

    public String computeAuditHash(String decryptedRaw) {
        return hashProvider.sha256(decryptedRaw);
    }

    private ParsedCredential parseJwt(String raw) throws ParseException {
        var jwt = SignedJWT.parse(raw);
        var claims = jwt.getJWTClaimsSet();

        var issuer = claims.getIssuer();
        var subject = claims.getSubject();
        var issuanceDate = claims.getIssueTime() != null ? claims.getIssueTime().toInstant() : Instant.now();
        var expirationDate = claims.getExpirationTime() != null ? claims.getExpirationTime().toInstant() : null;

        var credentialType = extractCredentialType(claims.getClaims());

        return new ParsedCredential(issuer, subject, issuanceDate, expirationDate, credentialType, null);
    }

    private ParsedCredential parseSdJwt(String raw) throws ParseException {
        var parts = raw.split("~");
        if (parts.length == 0 || parts[0].isBlank()) {
            throw new MalformedCredentialException("SD-JWT has no issuer-signed JWT");
        }

        var jwt = SignedJWT.parse(parts[0]);
        var claims = jwt.getJWTClaimsSet();

        var issuer = claims.getIssuer();
        var subject = claims.getSubject();
        var issuanceDate = claims.getIssueTime() != null ? claims.getIssueTime().toInstant() : Instant.now();
        var expirationDate = claims.getExpirationTime() != null ? claims.getExpirationTime().toInstant() : null;

        var credentialType = extractCredentialType(claims.getClaims());
        var vct = claims.getStringClaim("vct");

        return new ParsedCredential(issuer, subject, issuanceDate, expirationDate, credentialType, vct);
    }

    @SuppressWarnings("unchecked")
    private String extractCredentialType(Map<String, Object> claims) {
        // Try vc.type (W3C format)
        if (claims.containsKey("vc")) {
            var vc = claims.get("vc");
            if (vc instanceof Map<?, ?> vcMap && vcMap.containsKey("type")) {
                var types = vcMap.get("type");
                if (types instanceof java.util.List<?> list && !list.isEmpty()) {
                    // Return last type (most specific)
                    return list.get(list.size() - 1).toString();
                }
            }
        }
        // Try vct claim (SD-JWT VC)
        if (claims.containsKey("vct")) {
            return claims.get("vct").toString();
        }
        // Try type claim directly
        if (claims.containsKey("type")) {
            var types = claims.get("type");
            if (types instanceof java.util.List<?> list && !list.isEmpty()) {
                return list.get(list.size() - 1).toString();
            }
            return types.toString();
        }
        return "Unknown";
    }
}
