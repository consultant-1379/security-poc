/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.kaps.certificate.exception;

import com.ericsson.oss.itpf.security.kaps.exception.CertificateException;


/**
 * This exception is thrown to indicate that an exception has occurred during CSR generation
 * 
 * @author xramcho
 * 
 */
public class CSRGenerationException extends CertificateException {

    private static final long serialVersionUID = 358894277239527218L;

    /**
     * Constructs a new CSRGenerationException with detailed message
     * 
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public CSRGenerationException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CSRGenerationException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CSRGenerationException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CSRGenerationException with detailed message and cause
     * 
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public CSRGenerationException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
