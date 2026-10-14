package com.eudistack.ebw.domain.model;

import java.util.List;
import java.util.UUID;

/**
 * Data of the options to create a passkey (WebAuthn {@code PublicKeyCredentialCreationOptions}).
 *
 * @param requestPrf whether {@code extensions.prf} is requested (passkey custody in the tenant)
 */
public record RegistrationOptions(
        UUID ceremonyId,
        RelyingPartySettings relyingParty,
        byte[] userHandle,
        String userName,
        byte[] challenge,
        List<UserPasskey> excludeCredentials,
        boolean requestPrf
) {
}
