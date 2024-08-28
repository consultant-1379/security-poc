package com.ericsson.oss.services.cm.alias.exceptions;

public class CannotPersistAliasException extends RuntimeException {

    private static final long serialVersionUID = -7760893854256011025L;

    public CannotPersistAliasException(final String message) {
        super(message);
    }
}
