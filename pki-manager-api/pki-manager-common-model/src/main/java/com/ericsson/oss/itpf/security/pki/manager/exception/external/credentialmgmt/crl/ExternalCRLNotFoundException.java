/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl;

import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCRLException;

/**
 * Thrown to indicate that CRLs are not present for the corresponding entity.
 * 
 */
public class ExternalCRLNotFoundException extends ExternalCRLException {

    private static final long serialVersionUID = 6251727243298288430L;

    /**
     * Constructs a new ExternalCRLNotFoundException
     */
    public ExternalCRLNotFoundException() {
        super();
    }

    /**
     * Constructs a new ExternalCRLNotFoundException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public ExternalCRLNotFoundException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new ExternalCRLNotFoundException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public ExternalCRLNotFoundException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ExternalCRLNotFoundException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public ExternalCRLNotFoundException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
