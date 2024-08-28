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

public class PkiProfileMapperException extends Exception {

    /**
     *
     */
    public PkiProfileMapperException() {
    }

    /**
     * @param message
     */
    public PkiProfileMapperException(final String message) {
        super("PkiProfileMapperException: " + message);
    }

    /**
     * @param cause
     */
    public PkiProfileMapperException(final Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public PkiProfileMapperException(final String message, final Throwable cause) {
        super("PkiProfileMapperException: " + message, cause);
    }

}
