package com.ericsson.oss.services.cm.alias.exceptions;

public class CannotFindAliasException extends RuntimeException {

    private static final long serialVersionUID = -7760893854256011025L;

    public CannotFindAliasException(final String message) {
        super(message);
    }
}
