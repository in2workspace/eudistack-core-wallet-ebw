package com.eudistack.ebw.application.workflow;

import java.util.UUID;

/**
 * The authenticated session a Wallet Instance operation runs for: the account ({@code sub}), the session
 * ({@code sid}), its passkey ({@code pkid}) and the active instance it is bound to, {@code null} if none.
 */
public record WalletSession(UUID userId, UUID sessionId, UUID passkeyId, UUID walletInstanceId) {
}
