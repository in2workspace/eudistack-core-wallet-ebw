package com.eudistack.ebw.domain.model.audit;

/**
 * A third-party system the Wallet EBW calls, as the {@code ExternalSystemAccess} event describes it.
 *
 * @param systemType           catalogue {@code system_type}
 * @param system               registered name or host of the third party
 * @param authenticationMethod catalogue {@code authentication_method}
 */
public record ExternalSystemTarget(String systemType, String system, String authenticationMethod) {

    public static final String AUTHENTICATION_NONE = "None";
    public static final String AUTHENTICATION_BASIC = "Basic";

    private static final String SYSTEM_TYPE_MAIL_PROVIDER = "MailProvider";

    public static ExternalSystemTarget mailProvider(String system, String authenticationMethod) {
        return new ExternalSystemTarget(SYSTEM_TYPE_MAIL_PROVIDER, system, authenticationMethod);
    }
}
