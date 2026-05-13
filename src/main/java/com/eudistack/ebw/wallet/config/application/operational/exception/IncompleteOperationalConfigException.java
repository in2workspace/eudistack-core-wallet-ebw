package com.eudistack.ebw.wallet.config.application.operational.exception;

import java.util.List;
import java.util.Objects;

/**
 * Thrown by {@code OperationalConfigWriter} when required fields are missing or invalid
 * in the supplied {@link com.eudistack.ebw.wallet.config.domain.model.operational.OperationalConfig}.
 *
 * <p>Maps to HTTP {@code 409 Conflict} at the controller layer (Task 8). The field names
 * listed in {@link #invalidFields()} are logical names only — no secret values are included.
 *
 * <p>No Spring annotations on this class: it is a plain domain-application exception.
 */
public class IncompleteOperationalConfigException extends RuntimeException {

    private final List<String> invalidFields;

    /**
     * @param invalidFields the list of missing or invalid logical field names; must not be null
     */
    public IncompleteOperationalConfigException(List<String> invalidFields) {
        super("operational config is incomplete; missing or invalid fields: "
                + Objects.requireNonNull(invalidFields, "invalidFields must not be null"));
        this.invalidFields = List.copyOf(invalidFields);
    }

    /**
     * Returns an unmodifiable list of the logical field names that are missing or invalid.
     * Never contains secret values.
     */
    public List<String> invalidFields() {
        return invalidFields;
    }
}
