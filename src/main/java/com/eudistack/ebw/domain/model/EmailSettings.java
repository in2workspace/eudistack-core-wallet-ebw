package com.eudistack.ebw.domain.model;

import java.time.ZoneId;

/**
 * Email settings of a tenant (EUD-8 design §2.8): the language of an email when the holder's is unknown, and
 * the time zone of its dates.
 */
public record EmailSettings(String defaultLanguage, ZoneId zone) {

    public static final ZoneId DEFAULT_ZONE = ZoneId.of("Europe/Madrid");
    public static final EmailSettings DEFAULTS = new EmailSettings(EmailLanguage.DEFAULT, DEFAULT_ZONE);
}
