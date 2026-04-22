package com.eudistack.ebw.infrastructure.controller.dto;

import com.eudistack.ebw.infrastructure.controller.validation.AllowedEmailDomain;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank @Email @Size(max = 254) @AllowedEmailDomain String email
) {
}
