package com.eudistack.ebw.infrastructure.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.UUID;

/**
 * Authenticated wallet session: the account ({@code sub}), the session ({@code sid}) and the
 * passkey that opened it ({@code pkid}), from a verified access token of the request's tenant.
 */
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final UUID userId;
    private final String email;
    private final UUID sessionId;
    private final UUID passkeyId;
    private final UUID walletInstanceId;

    public JwtAuthenticationToken(UUID userId, String email, UUID sessionId, UUID passkeyId,
                                  Collection<? extends GrantedAuthority> authorities) {
        this(userId, email, sessionId, passkeyId, null, authorities);
    }

    /** @param walletInstanceId active Wallet Instance the session is bound to, {@code null} if none (EUD-15) */
    public JwtAuthenticationToken(UUID userId, String email, UUID sessionId, UUID passkeyId, UUID walletInstanceId,
                                  Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.userId = userId;
        this.email = email;
        this.sessionId = sessionId;
        this.passkeyId = passkeyId;
        this.walletInstanceId = walletInstanceId;
        setAuthenticated(true);
    }

    /** The same session, bound to {@code walletInstanceId}. */
    public JwtAuthenticationToken withWalletInstance(UUID walletInstanceId) {
        return new JwtAuthenticationToken(userId, email, sessionId, passkeyId, walletInstanceId, getAuthorities());
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

    public UUID getSessionId() {
        return sessionId;
    }

    public UUID getPasskeyId() {
        return passkeyId;
    }

    public UUID getWalletInstanceId() {
        return walletInstanceId;
    }
}
