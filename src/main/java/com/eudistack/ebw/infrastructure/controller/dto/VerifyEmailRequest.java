package com.eudistack.ebw.infrastructure.controller.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record VerifyEmailRequest(
        @NotBlank @Email @Size(max = 254) String email,
        @NotBlank @Size(max = 6) String code
) {
}
