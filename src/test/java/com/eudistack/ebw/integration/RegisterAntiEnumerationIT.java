package com.eudistack.ebw.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * FR-05 / AC-03 (EUD-8): {@code POST /auth/register} answers the same, with no body, whether the
 * email has an account or not, and creates nothing.
 */
class RegisterAntiEnumerationIT extends IntegrationTestBase {

    @BeforeEach
    void setUp() {
        setupEmailCapture();
        capturedOtps.clear();
    }

    @Test
    void register_existingAndNewEmail_returnIdenticalEmptyAccepted() {
        var auth = authClient();
        var existingEmail = "anti-enum-existing-" + System.nanoTime() + "@example.com";
        var newEmail = "anti-enum-new-" + System.nanoTime() + "@example.com";
        auth.verifyEmail(existingEmail);

        var existing = auth.requestCode(existingEmail).expectStatus().isAccepted()
                .expectBody().returnResult();
        var unknown = auth.requestCode(newEmail).expectStatus().isAccepted()
                .expectBody().returnResult();

        assertThat(existing.getResponseBody()).isNull();
        assertThat(unknown.getResponseBody()).isNull();
        assertThat(capturedOtps).containsKeys(existingEmail, newEmail);
    }

    @Test
    void register_unknownEmail_createsNoAccount() {
        var email = "anti-enum-nothing-" + System.nanoTime() + "@example.com";

        webClient.post().uri("/api/v1/auth/register").bodyValue(Map.of("email", email))
                .exchange().expectStatus().isAccepted();

        assertThat(query("SELECT id FROM wallet_user WHERE email = '" + email + "'")).isEmpty();
    }
}
