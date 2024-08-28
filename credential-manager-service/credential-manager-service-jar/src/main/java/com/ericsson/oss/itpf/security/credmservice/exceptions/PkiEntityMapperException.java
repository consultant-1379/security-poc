/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.exceptions;

public class PkiEntityMapperException extends Exception {

    /**
     *
     */
    public PkiEntityMapperException() {
    }

    /**
     * @param message
     */
    public PkiEntityMapperException(final String message) {
        super("PkiEntityMapperException: " + message);
    }

    /**
     * @param cause
     */
    public PkiEntityMapperException(final Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public PkiEntityMapperException(final String message, final Throwable cause) {
        super("PkiEntityMapperException: " + message, cause);
    }

}
