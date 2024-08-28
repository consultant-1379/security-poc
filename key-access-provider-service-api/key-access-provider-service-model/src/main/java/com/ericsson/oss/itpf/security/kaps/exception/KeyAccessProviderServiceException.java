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
package com.ericsson.oss.itpf.security.kaps.exception;

/**
 * This exception is thrown to indicate any internal database errors or any unconditional exceptions.
 * 
 * @author xramcho
 * 
 */
public class KeyAccessProviderServiceException extends KAPSRuntimeException {

    private static final long serialVersionUID = 3926209120196500953L;

    /**
     * Constructs a new KeyAccessProviderServiceException with detailed message
     * 
     * @param errorMessage
     *            the detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
     */
    public KeyAccessProviderServiceException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new KeyAccessProviderServiceException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public KeyAccessProviderServiceException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new KeyAccessProviderServiceException with detailed message and cause
     * 
     * @param errorMessage
     *            the detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the {@link #getCause()} method)
     */
    public KeyAccessProviderServiceException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
