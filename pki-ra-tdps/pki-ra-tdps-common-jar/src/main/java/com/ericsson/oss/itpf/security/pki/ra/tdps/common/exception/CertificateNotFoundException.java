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
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception;

import javax.ejb.ApplicationException;

/**
 * This exception is thrown when Certificate is not found in the Database with a given combination of Entity Name and EntityType. Reason could certificate is not published to Trust Distribution
 * Service or is was unpublished through WebCLI and yet a Rest request is fired to TrustDistribution service.
 * 
 * @author tcsdemi
 *
 */
@ApplicationException(rollback = true)
public class CertificateNotFoundException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new CertificateNotFoundException
     */
    public CertificateNotFoundException() {
        super();
    }

    /**
     * Constructs a new CertificateNotFoundException with message
     * 
     * @param message
     *            The detailed message
     */
    public CertificateNotFoundException(final String message) {
        super(message);

    }

    /**
     * Constructs a new CertificateNotFoundException with message and cause
     * 
     * @param message
     *            The detailed message
     * @param cause
     *            the cause which is used for later retrieval
     */
    public CertificateNotFoundException(final String message, final Throwable cause) {
        super(message, cause);

    }

    /**
     * Constructs a new CertificateNotFoundException with cause
     * 
     * @param cause
     *            the cause which is used for later retrieval
     */
    public CertificateNotFoundException(final Throwable cause) {
        super(cause);

    }

}
