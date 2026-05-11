package com.eudistack.ebw.infrastructure.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;
import java.util.UUID;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final UUID userId;
    private final String email;

    /**
     * Creates an authentication token with no granted authorities — the common case for
     * ordinary EBW user JWTs which carry no scope claim.
     */
    public JwtAuthenticationToken(UUID userId, String email) {
        this(userId, email, AuthorityUtils.NO_AUTHORITIES);
    }

    /**
     * Creates an authentication token with the supplied granted authorities (e.g. derived from a
     * {@code scope}/{@code scp} JWT claim — see {@code JwtAuthenticationWebFilter}).
     */
    public JwtAuthenticationToken(UUID userId, String email,
                                  Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.userId = userId;
        this.email = email;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return userId;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getEmail() {
        return email;
    }
}
