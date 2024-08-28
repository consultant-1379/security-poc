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
package com.ericsson.oss.itpf.security.pki.manager.exception.crl;

import com.ericsson.oss.itpf.security.pki.manager.exception.CRLException;

/**
 * This exception is thrown when any error arises while generating the CRL.
 *
 * @author xbensar
 */
public class CRLGenerationException extends CRLException  {

    private static final long serialVersionUID = 7799050166138641240L;

    /**
     * Constructs a new CRLGenerationException with detailed message
     * 
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CRLGenerationException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CRLGenerationException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CRLGenerationException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CRLGenerationException with detailed message and cause
     * 
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CRLGenerationException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
