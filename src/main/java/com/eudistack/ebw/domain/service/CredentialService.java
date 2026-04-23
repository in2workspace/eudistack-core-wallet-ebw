package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.CredentialFormat;
import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.CredentialStatusTransition;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.model.exception.MalformedCredentialException;
import com.eudistack.ebw.domain.model.exception.UnsupportedFormatException;
import com.eudistack.ebw.domain.spi.CredentialEncryptor;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.infrastructure.controller.dto.VerifiableCredentialResponse;
import com.eudistack.ebw.infrastructure.controller.dto.VerifiableCredentialResponse.CredentialStatusDto;
import com.eudistack.ebw.infrastructure.controller.dto.VerifiableCredentialResponse.IssuerDto;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.text.ParseException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class CredentialService {

    private static final Logger log = LoggerFactory.getLogger(CredentialService.class);

    private static final Set<String> STANDARD_JWT_CLAIMS = Set.of(
            "iss", "iat", "exp", "nbf", "sub", "jti", "cnf", "vct", "status",
            "type", "@context", "id", "issuer", "validFrom", "validUntil",
            "issuanceDate", "expirationDate", "credentialStatus"
    );

    private final HashProvider hashProvider;
    private final ObjectMapper objectMapper;

    public CredentialService(HashProvider hashProvider, ObjectMapper objectMapper) {
        this.hashProvider = hashProvider;
        this.objectMapper = objectMapper;
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

    public VerifiableCredentialResponse toVerifiableCredential(
            WalletCredential credential, CredentialEncryptor encryptor) {
        if (credential.getCredentialRaw() == null) {
            log.warn("credential_raw is null for credential {}, returning fallback", credential.getId());
            return buildFallback(credential);
        }
        String raw;
        try {
            raw = encryptor.decrypt(credential.getCredentialRaw());
        } catch (Exception e) {
            log.error("Decrypt failed for credential {}: {}", credential.getId(), e.getMessage(), e);
            return buildFallback(credential);
        }

        try {
            return switch (credential.getFormat()) {
                case DC_SD_JWT -> buildFromSdJwt(credential, raw);
                case JWT_VC_JSON -> buildFromJwtVc(credential, raw);
            };
        } catch (Exception e) {
            log.error("Parse failed for credential {} format={}: {}", credential.getId(), credential.getFormat(), e.getMessage(), e);
            return buildFallback(credential);
        }
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

    // --- Private: SD-JWT parsing ---

    private VerifiableCredentialResponse buildFromSdJwt(WalletCredential credential, String raw)
            throws Exception {
        var parts = raw.split("~");
        if (parts.length == 0 || parts[0].isBlank()) {
            throw new MalformedCredentialException("SD-JWT has no issuer-signed JWT");
        }

        var jwt = SignedJWT.parse(parts[0]);
        var claims = jwt.getJWTClaimsSet();
        var claimsMap = claims.getClaims();

        // Parse disclosures: parts[1..n], skip last if it looks like a JWT (contains two dots)
        var disclosures = new HashMap<String, Object>();
        for (int i = 1; i < parts.length; i++) {
            String part = parts[i];
            if (part.isBlank()) {
                continue;
            }
            // A key-binding JWT contains exactly two '.' characters
            if (part.chars().filter(c -> c == '.').count() == 2) {
                continue;
            }
            try {
                byte[] decoded = Base64.getUrlDecoder().decode(part);
                List<Object> disclosure = objectMapper.readValue(decoded,
                        new TypeReference<List<Object>>() {});
                if (disclosure.size() >= 3) {
                    disclosures.put(disclosure.get(1).toString(), disclosure.get(2));
                }
            } catch (Exception ignored) {
                // Skip malformed disclosures
            }
        }

        var id = resolveId(credential);
        var type = resolveType(claimsMap, disclosures);
        var context = resolveContext(claimsMap);
        var issuer = resolveIssuer(claimsMap);
        var validFrom = resolveValidFrom(claims);
        var validUntil = resolveValidUntil(claims);
        var credentialStatus = resolveCredentialStatus(claimsMap);
        var credentialSubject = resolveCredentialSubjectSdJwt(claimsMap, disclosures);
        var name = resolveStringClaim(claimsMap, "name");
        var description = resolveStringClaim(claimsMap, "description");

        return new VerifiableCredentialResponse(
                context, id, type, credential.getStatus().name(),
                name, description, issuer, validFrom, validUntil,
                credentialSubject, credentialStatus, raw,
                credential.getFormat().getValue()
        );
    }

    // --- Private: JWT VC JSON parsing ---

    private VerifiableCredentialResponse buildFromJwtVc(WalletCredential credential, String raw)
            throws Exception {
        var jwt = SignedJWT.parse(raw);
        var claims = jwt.getJWTClaimsSet();
        var claimsMap = claims.getClaims();

        // W3C JWT VCs nest most claims under "vc"
        @SuppressWarnings("unchecked")
        var vcClaims = claimsMap.containsKey("vc") && claimsMap.get("vc") instanceof Map<?, ?> vcMap
                ? (Map<String, Object>) vcMap
                : claimsMap;

        var id = resolveId(credential);
        var type = resolveType(vcClaims);
        var context = resolveContext(vcClaims);
        var issuer = resolveIssuer(claimsMap);
        var validFrom = resolveValidFrom(claims);
        var validUntil = resolveValidUntil(claims);
        var credentialStatus = resolveCredentialStatus(vcClaims);
        var credentialSubject = resolveCredentialSubjectJwtVc(vcClaims);
        var name = resolveStringClaim(vcClaims, "name");
        var description = resolveStringClaim(vcClaims, "description");

        return new VerifiableCredentialResponse(
                context, id, type, credential.getStatus().name(),
                name, description, issuer, validFrom, validUntil,
                credentialSubject, credentialStatus, raw,
                credential.getFormat().getValue()
        );
    }

    // --- Private: field resolvers ---

    private String resolveId(WalletCredential credential) {
        return credential.getId().toString();
    }

    @SuppressWarnings("unchecked")
    private List<String> resolveType(Map<String, Object> claims) {
        return resolveType(claims, Map.of());
    }

    @SuppressWarnings("unchecked")
    private List<String> resolveType(Map<String, Object> claims, Map<String, Object> disclosures) {
        if (claims.containsKey("type") && claims.get("type") instanceof List<?> types) {
            return (List<String>) types;
        }
        // vct can be in the JWT claims or in a disclosure
        String vct = null;
        if (claims.containsKey("vct") && claims.get("vct") instanceof String v) {
            vct = v;
        } else if (disclosures.containsKey("vct") && disclosures.get("vct") instanceof String v) {
            vct = v;
        }
        if (vct != null) {
            return List.of("VerifiableCredential", vct);
        }
        return List.of("VerifiableCredential");
    }

    @SuppressWarnings("unchecked")
    private List<String> resolveContext(Map<String, Object> claims) {
        if (claims.containsKey("@context") && claims.get("@context") instanceof List<?> ctx) {
            return (List<String>) ctx;
        }
        return List.of("https://www.w3.org/2018/credentials/v1");
    }

    @SuppressWarnings("unchecked")
    private IssuerDto resolveIssuer(Map<String, Object> claims) {
        Object issuerClaim = claims.containsKey("issuer") ? claims.get("issuer") : claims.get("iss");
        if (issuerClaim instanceof String issuerStr) {
            return new IssuerDto(issuerStr, null, null, null, null, null);
        }
        if (issuerClaim instanceof Map<?, ?> issuerMap) {
            var m = (Map<String, Object>) issuerMap;
            return new IssuerDto(
                    stringOrNull(m, "id"),
                    stringOrNull(m, "organization"),
                    stringOrNull(m, "organizationIdentifier"),
                    stringOrNull(m, "country"),
                    stringOrNull(m, "commonName"),
                    stringOrNull(m, "serialNumber")
            );
        }
        return new IssuerDto("unknown", null, null, null, null, null);
    }

    private String resolveValidFrom(com.nimbusds.jwt.JWTClaimsSet claims) throws ParseException {
        var validFromStr = claims.getStringClaim("validFrom");
        if (validFromStr != null) {
            return validFromStr;
        }
        var issuanceDate = claims.getStringClaim("issuanceDate");
        if (issuanceDate != null) {
            return issuanceDate;
        }
        if (claims.getIssueTime() != null) {
            return DateTimeFormatter.ISO_INSTANT.format(claims.getIssueTime().toInstant());
        }
        return null;
    }

    private String resolveValidUntil(com.nimbusds.jwt.JWTClaimsSet claims) throws ParseException {
        var validUntilStr = claims.getStringClaim("validUntil");
        if (validUntilStr != null) {
            return validUntilStr;
        }
        var expirationDate = claims.getStringClaim("expirationDate");
        if (expirationDate != null) {
            return expirationDate;
        }
        if (claims.getExpirationTime() != null) {
            return DateTimeFormatter.ISO_INSTANT.format(claims.getExpirationTime().toInstant());
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private CredentialStatusDto resolveCredentialStatus(Map<String, Object> claims) {
        // Direct credentialStatus claim
        if (claims.containsKey("credentialStatus") && claims.get("credentialStatus") instanceof Map<?, ?> csMap) {
            var m = (Map<String, Object>) csMap;
            return new CredentialStatusDto(
                    stringOrNull(m, "id"),
                    stringOrNull(m, "type"),
                    stringOrNull(m, "statusPurpose"),
                    stringOrNull(m, "statusListIndex"),
                    stringOrNull(m, "statusListCredential")
            );
        }
        // status.status_list (SD-JWT VC draft) fallback
        if (claims.containsKey("status") && claims.get("status") instanceof Map<?, ?> statusMap) {
            var statusListObj = ((Map<?, ?>) statusMap).get("status_list");
            if (statusListObj instanceof Map<?, ?> slMap) {
                var m = (Map<String, Object>) slMap;
                var idx = m.containsKey("idx") ? m.get("idx").toString() : "";
                var uri = m.containsKey("uri") ? m.get("uri").toString() : "";
                return new CredentialStatusDto(uri, "StatusList2021Entry", "revocation", idx, uri);
            }
        }
        return new CredentialStatusDto("", "", "", "", "");
    }

    private Object resolveCredentialSubjectSdJwt(Map<String, Object> claims,
            Map<String, Object> disclosures) {
        if (claims.containsKey("credentialSubject") && claims.get("credentialSubject") instanceof Map<?, ?>) {
            return claims.get("credentialSubject");
        }
        if (!disclosures.isEmpty()) {
            // Return disclosures filtered to non-standard keys
            var subject = new HashMap<String, Object>();
            disclosures.forEach((k, v) -> {
                if (!STANDARD_JWT_CLAIMS.contains(k)) {
                    subject.put(k, v);
                }
            });
            if (!subject.isEmpty()) {
                return subject;
            }
        }
        return Map.of();
    }

    private Object resolveCredentialSubjectJwtVc(Map<String, Object> claims) {
        if (claims.containsKey("credentialSubject") && claims.get("credentialSubject") instanceof Map<?, ?> cs) {
            return cs;
        }
        return Map.of();
    }

    private String resolveStringClaim(Map<String, Object> claims, String key) {
        return claims.containsKey(key) && claims.get(key) instanceof String value ? value : null;
    }

    private String stringOrNull(Map<String, Object> map, String key) {
        return map.containsKey(key) && map.get(key) instanceof String value ? value : null;
    }

    // --- Private: fallback response (parsing failed) ---

    private VerifiableCredentialResponse buildFallback(WalletCredential credential) {
        var issuer = new IssuerDto(credential.getIssuer(), null, null, null, null, null);
        var validFrom = credential.getIssuanceDate() != null
                ? DateTimeFormatter.ISO_INSTANT.format(credential.getIssuanceDate())
                : null;
        var validUntil = credential.getExpirationDate() != null
                ? DateTimeFormatter.ISO_INSTANT.format(credential.getExpirationDate())
                : null;
        return new VerifiableCredentialResponse(
                List.of("https://www.w3.org/2018/credentials/v1"),
                credential.getId().toString(),
                List.of("VerifiableCredential"),
                credential.getStatus().name(),
                null, null, issuer, validFrom, validUntil,
                Map.of(),
                new CredentialStatusDto("", "", "", "", ""),
                null,
                credential.getFormat().getValue()
        );
    }

    // --- Private: JWT parsing helpers (used by parseCredential) ---

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
