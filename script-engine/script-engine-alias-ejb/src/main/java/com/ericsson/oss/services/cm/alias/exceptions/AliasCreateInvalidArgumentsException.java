package com.ericsson.oss.services.cm.alias.exceptions;

public class AliasCreateInvalidArgumentsException extends Exception {

    private static final long serialVersionUID = 4851825692561443973L;

    private final int errorCode;

    public AliasCreateInvalidArgumentsException(final int errorCode) {
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return errorCode;
    }
}
