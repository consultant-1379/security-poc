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
package com.ericsson.oss.itpf.security.pki.ra.scep.exception;

/**
 * CrlCacheException is thrown when any error occurred while processing CRLs like(CertificateException, CRLException..).
 * 
 * @author xchowja
 *
 */
public class CrlCacheException extends RuntimeException {

    private static final long serialVersionUID = 4161359067064138174L;

    /**
     * Creates an exception with a message.
     * 
     * @param errorMessage
     *            The message describing the error.
     * @param cause
     *            The cause of the exception.
     */
    public CrlCacheException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

    /**
     * @param msg
     *            is the description of the message.
     */
    public CrlCacheException(final String msg) {
        super(msg);
    }
}
