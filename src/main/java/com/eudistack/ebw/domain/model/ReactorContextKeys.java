package com.eudistack.ebw.domain.model;

public final class ReactorContextKeys {

    public static final String TENANT_DOMAIN = "tenantDomain";

    /** DPoP-bound holder UUID string. Set by {@code PasskeyPrfKeyManagerController} from the JWT principal. */
    public static final String HOLDER_ID = "holderId";

    /** Passkey of the session (JWT {@code pkid}). Set by {@code PasskeyPrfKeyManagerController}. */
    public static final String PASSKEY_ID = "passkeyId";

    /**
     * Supported language ({@code es}, {@code ca}, {@code en}) the request's {@code Accept-Language} prefers, the
     * Wallet App's active language (EUD-8 AD-10). Absent when the header names none. Set by
     * {@code RequestLanguageWebFilter}.
     */
    public static final String REQUEST_LANGUAGE = "requestLanguage";

    private ReactorContextKeys() {}
}
