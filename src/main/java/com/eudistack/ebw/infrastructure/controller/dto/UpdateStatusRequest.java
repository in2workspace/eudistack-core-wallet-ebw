package com.eudistack.ebw.infrastructure.controller.dto;

import jakarta.validation.constraints.NotBlank;

public record UpdateStatusRequest(
        @NotBlank String status
) {}
