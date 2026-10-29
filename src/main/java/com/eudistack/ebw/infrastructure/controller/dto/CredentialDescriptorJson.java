package com.eudistack.ebw.infrastructure.controller.dto;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

/** {@code PublicKeyCredentialDescriptorJSON}. */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record CredentialDescriptorJson(String type, String id, List<String> transports) {

    public static CredentialDescriptorJson from(UserPasskey passkey) {
        return new CredentialDescriptorJson("public-key", passkey.getCredentialId(), passkey.getTransports());
    }
}
