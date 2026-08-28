package com.eudistack.ebw.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC-04 / NFR-S-01: POST /register MUST return an identical response (status + body)
 * whether the email already has an account or not, so the endpoint never reveals
 * account existence (anti-enumeration).
 */
class RegisterAntiEnumerationIT extends IntegrationTestBase {

    @BeforeEach
    void setUp() {
        setupEmailCapture();
        capturedOtps.clear();
    }

    @Test
    void register_existingAndNewEmail_returnIdenticalResponse() {
        var existingEmail = "anti-enum-existing-" + System.nanoTime() + "@example.com";
        var newEmail = "anti-enum-new-" + System.nanoTime() + "@example.com";

        // Pre-condition: existingEmail already has an account
        webClient.post().uri("/api/v1/auth/register")
                .bodyValue(Map.of("email", existingEmail))
                .exchange()
                .expectStatus().isOk();

        var existingEmailStatus = webClient.post().uri("/api/v1/auth/register")
                .bodyValue(Map.of("email", existingEmail))
                .exchange()
                .expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult();

        var newEmailStatus = webClient.post().uri("/api/v1/auth/register")
                .bodyValue(Map.of("email", newEmail))
                .exchange()
                .expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult();

        assertThat(existingEmailStatus.getStatus()).isEqualTo(newEmailStatus.getStatus());
        assertThat(existingEmailStatus.getResponseBody()).isEqualTo(newEmailStatus.getResponseBody());

        // Both requests must have triggered an OTP send (register never signals existence via side effects)
        assertThat(capturedOtps).containsKeys(existingEmail, newEmail);
    }
}
