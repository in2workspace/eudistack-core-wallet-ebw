package com.eudistack.ebw.infrastructure.controller.dto;

import com.eudistack.ebw.domain.model.RegistrationTicketIssued;

public record VerifyEmailResponse(String registrationTicket, long expiresIn, boolean hasPasskeys) {

    public static VerifyEmailResponse from(RegistrationTicketIssued issued) {
        return new VerifyEmailResponse(issued.ticket(), issued.expiresIn(), issued.hasPasskeys());
    }
}
