package com.eudistack.ebw.infrastructure.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdatePasskeyRequest(
        @NotBlank @Size(min = 1, max = 100) String displayName
) {
}
