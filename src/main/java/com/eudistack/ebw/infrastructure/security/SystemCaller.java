package com.eudistack.ebw.infrastructure.security;

/**
 * System authenticated with a valid system token (design §2.6).
 *
 * @param id identifier of the system ({@code sub} of the token), recorded as who requested a ticket
 */
public record SystemCaller(String id) {
}
