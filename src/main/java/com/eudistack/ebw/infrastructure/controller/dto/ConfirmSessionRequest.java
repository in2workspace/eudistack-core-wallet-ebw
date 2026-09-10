package com.eudistack.ebw.infrastructure.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ConfirmSessionRequest(
        @NotBlank @Size(max = 128) String refreshToken
) {
}
