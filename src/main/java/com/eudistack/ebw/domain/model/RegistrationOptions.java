package com.eudistack.ebw.domain.model;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
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

    @Override
    public boolean equals(Object other) {
        return other instanceof RegistrationOptions(var otherCeremonyId, var otherRelyingParty, var otherUserHandle,
                                                    var otherUserName, var otherChallenge, var otherExcludeCredentials,
                                                    var otherRequestPrf)
                && requestPrf == otherRequestPrf
                && Objects.equals(ceremonyId, otherCeremonyId)
                && Objects.equals(relyingParty, otherRelyingParty)
                && Arrays.equals(userHandle, otherUserHandle)
                && Objects.equals(userName, otherUserName)
                && Arrays.equals(challenge, otherChallenge)
                && Objects.equals(excludeCredentials, otherExcludeCredentials);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(ceremonyId, relyingParty, userName, excludeCredentials, requestPrf);
        result = 31 * result + Arrays.hashCode(userHandle);
        return 31 * result + Arrays.hashCode(challenge);
    }

    @Override
    public String toString() {
        return "RegistrationOptions[ceremonyId=" + ceremonyId + ", relyingParty=" + relyingParty
                + ", userHandle=[redacted], userName=[redacted], challenge=[redacted], excludeCredentials="
                + (excludeCredentials == null ? 0 : excludeCredentials.size()) + " passkeys, requestPrf="
                + requestPrf + "]";
    }
}
