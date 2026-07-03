package com.eudistack.ebw.domain.model;

public final class ReactorContextKeys {

    public static final String TENANT_DOMAIN = "tenantDomain";

    /** DPoP-bound holder UUID string. Set by {@code HybridKeyManagerController} from the JWT principal. */
    public static final String HOLDER_ID = "holderId";

    private ReactorContextKeys() {}
}
