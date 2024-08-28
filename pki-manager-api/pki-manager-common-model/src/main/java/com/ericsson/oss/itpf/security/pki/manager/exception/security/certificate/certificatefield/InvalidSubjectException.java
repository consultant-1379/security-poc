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
package com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateFieldException;

/**
 * This exception is thrown when the invalid subject is provided as part of the request.
 */
public class InvalidSubjectException extends CertificateFieldException {

    private static final long serialVersionUID = -1567427096858137247L;

    /**
     * Constructs a new InvalidSubjectException
     */
    public InvalidSubjectException() {
        super();
    }

    /**
     * Constructs a new InvalidSubjectException with detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public InvalidSubjectException(final String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidSubjectException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public InvalidSubjectException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidSubjectException with detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */

    public InvalidSubjectException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
