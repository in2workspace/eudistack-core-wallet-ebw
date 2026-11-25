package com.eudistack.ebw.domain.model;

import java.time.Instant;

/**
 * Content of the email that confirms a complete sign-up (EUD-15 wireframes "Alta completa", FR-08): the first
 * device of an account created with the email and the code. No links: whoever created it verified the email.
 *
 * @param createdAt  when the device was registered
 * @param deviceName name the device was registered with
 */
public record AccountCompleteNotice(Instant createdAt, String deviceName) {
}
