package com.ericsson.oss.itpf.security.kaps.crl.exception;

import com.ericsson.oss.itpf.security.kaps.exception.CRLException;

/**
 * This exception is thrown to indicate that an exception has occurred during CRL Signing.
 *
 * @author xramich
 *
 */
public class SignCRLException extends CRLException {

    private static final long serialVersionUID = -3154485046776571863L;

    /**
     * Constructs a new SignCRLException with detailed message
     *
     * @param message
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */

    public SignCRLException(final String message) {
        super(message);

    }

    /**
     * Constructs a new SignCRLException with cause
     *
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public SignCRLException(final Throwable cause) {
        super(cause);

    }

    /**
     * Constructs a new SignCRLException with detailed message and cause
     *
     * @param message
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public SignCRLException(final String message, final Throwable cause) {
        super(message, cause);

    }
}
