package com.eudistack.ebw.infrastructure.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterPasskeyRequest(
        @NotBlank @Size(max = 1024) String credentialId,
        @NotBlank @Size(min = 1, max = 100) String displayName,
        @Size(max = 512) String userAgent
) {
}
