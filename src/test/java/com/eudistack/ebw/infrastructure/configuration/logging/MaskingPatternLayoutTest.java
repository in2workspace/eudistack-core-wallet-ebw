package com.eudistack.ebw.infrastructure.configuration.logging;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static com.eudistack.ebw.infrastructure.configuration.logging.MaskingPatternLayout.REPLACEMENT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MaskingPatternLayoutTest {

    private static final String JWT_SAMPLE =
            "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    private static final String USER_ID = "550e8400-e29b-41d4-a716-446655440000";
    private static final String CREDENTIAL_ID = "9B2F7C1E-3A4D-4E5F-8A6B-7C8D9E0F1A2B";

    private MaskingPatternLayout layout;

    @BeforeEach
    void setUp() {
        LoggerContext context = new LoggerContext();
        layout = new MaskingPatternLayout();
        layout.setContext(context);
        layout.setPattern("%msg");
        layout.start();
    }

    @AfterEach
    void tearDown() {
        layout.stop();
    }

    // ─── mask() – Edge cases ──────────────────────────────────────────────────

    @Test
    void mask_NullInput_ReturnsNull() {
        assertThat(MaskingPatternLayout.mask(null)).isNull();
    }

    @Test
    void mask_BlankString_ReturnsBlankString() {
        assertThat(MaskingPatternLayout.mask("   ")).isBlank();
    }

    // ─── mask() – Email ───────────────────────────────────────────────────────

    @Test
    void mask_EmailEmbeddedInSentence_MasksOnlyEmail() {
        String result = MaskingPatternLayout.mask("Verification code sent to holder@empresa.com");

        assertThat(result).isEqualTo("Verification code sent to " + REPLACEMENT);
    }

    @Test
    void mask_EmailWithSubdomainAndPlusSuffix_MasksEmail() {
        String result = MaskingPatternLayout.mask("Sending email to john.doe+filter@mail.company.org");

        assertThat(result).doesNotContain("john.doe+filter@mail.company.org");
    }

    // ─── mask() – JWT and bearer tokens ───────────────────────────────────────

    @Test
    void mask_JwtEmbeddedInLogMessage_MasksJwt() {
        String result = MaskingPatternLayout.mask("Validating token " + JWT_SAMPLE + " for tenant sandbox");

        assertThat(result).isEqualTo("Validating token " + REPLACEMENT + " for tenant sandbox");
    }

    @Test
    void mask_BearerOpaqueToken_PreservesKeywordAndMasksValue() {
        String result = MaskingPatternLayout.mask("header: bearer someOpaqueToken123");

        assertThat(result)
                .containsIgnoringCase("bearer " + REPLACEMENT)
                .doesNotContain("someOpaqueToken123");
    }

    // ─── mask() – OTP, tokens and secrets as key=value / JSON fields ─────────

    @Test
    void mask_OtpCodeAsJsonField_MasksCode() {
        String result = MaskingPatternLayout.mask("{\"email\":\"a@b.io\",\"code\":\"482913\"}");

        assertThat(result).doesNotContain("482913").doesNotContain("a@b.io");
    }

    @Test
    void mask_CodeAsKeyValue_MasksCode() {
        String result = MaskingPatternLayout.mask("Verifying code=482913 for tenant sandbox");

        assertThat(result).isEqualTo("Verifying code=" + REPLACEMENT + " for tenant sandbox");
    }

    @Test
    void mask_AlphanumericCodeAsKeyValue_MasksCode() {
        String result = MaskingPatternLayout.mask("Exchanging code=SplxlOBeZQQYbYS6WxSbIA for tokens");

        assertThat(result).isEqualTo("Exchanging code=" + REPLACEMENT + " for tokens");
    }

    @Test
    void mask_OtpAsKeyValue_MasksOtp() {
        String result = MaskingPatternLayout.mask("Verifying otp=482913 for tenant sandbox");

        assertThat(result).isEqualTo("Verifying otp=" + REPLACEMENT + " for tenant sandbox");
    }

    @Test
    void mask_CamelCaseRefreshTokenAsJsonField_MasksToken() {
        String result = MaskingPatternLayout.mask("{\"refreshToken\":\"rT_abc123\"}");

        assertThat(result).doesNotContain("rT_abc123");
    }

    @Test
    void mask_SnakeCaseAccessTokenAsKeyValue_MasksToken() {
        String result = MaskingPatternLayout.mask("access_token=opaqueValue&token_type=Bearer");

        assertThat(result).doesNotContain("opaqueValue").contains("token_type=Bearer");
    }

    @Test
    void mask_ClientSecretAsJsonField_MasksSecret() {
        String result = MaskingPatternLayout.mask("{\"client_secret\":\"oauth2ClientSecret\"}");

        assertThat(result).doesNotContain("oauth2ClientSecret");
    }

    @Test
    void mask_PasswordAsQueryParam_MasksPassword() {
        String result = MaskingPatternLayout.mask("POST /token password=p@ssw0rd&grant_type=password");

        assertThat(result).doesNotContain("p@ssw0rd");
    }

    // ─── mask() – Holder, credential and session identifiers (UUID) ──────────

    @Test
    void mask_UserIdAndCredentialIdInWorkflowLog_MasksBothIds() {
        String input = "Credential deleted: id=" + CREDENTIAL_ID + ", userId=" + USER_ID;

        String result = MaskingPatternLayout.mask(input);

        assertThat(result).isEqualTo("Credential deleted: id=" + REPLACEMENT + ", userId=" + REPLACEMENT);
    }

    @Test
    void mask_UuidWithoutKey_MasksUuid() {
        String result = MaskingPatternLayout.mask("Refresh token reuse detected; ending session " + USER_ID);

        assertThat(result).isEqualTo("Refresh token reuse detected; ending session " + REPLACEMENT);
    }

    // ─── mask() – False positive prevention ──────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "Application started successfully on port 8080",
            "[wallet-ebw,4bf92f3577b34da6a3ce929d0e0e4736,00f067aa0ba902b7]",
            "error_code=expired_code notsecret=value",
            "Email verification rejected: invalid_code",
            "Failed to send a verification code: org.springframework.mail.MailSendException",
            "Failed to resolve name. status=Status{code=UNAVAILABLE, description=Unable to resolve host}",
            "{\"code\":\"invalid_request\"}",
            "Calling external service at https://api.example.com/v1/resources",
            "eyJ.onlyone"
    })
    void mask_NoSensitiveData_ReturnsUnchanged(String input) {
        assertThat(MaskingPatternLayout.mask(input)).isEqualTo(input);
    }

    // ─── doLayout() ───────────────────────────────────────────────────────────

    @Test
    void doLayout_MessageWithEmailAndUserId_MasksBoth() {
        ILoggingEvent event = mock(ILoggingEvent.class);
        when(event.getFormattedMessage()).thenReturn("Activity recorded for holder@empresa.com userId=" + USER_ID);

        String result = layout.doLayout(event);

        assertThat(result)
                .doesNotContain("holder@empresa.com")
                .doesNotContain(USER_ID);
    }

    @Test
    void doLayout_MessageWithNoSensitiveData_ReturnsFormattedMessageUnchanged() {
        ILoggingEvent event = mock(ILoggingEvent.class);
        when(event.getFormattedMessage()).thenReturn("Scheduler triggered at fixed rate");

        assertThat(layout.doLayout(event)).isEqualTo("Scheduler triggered at fixed rate");
    }
}
