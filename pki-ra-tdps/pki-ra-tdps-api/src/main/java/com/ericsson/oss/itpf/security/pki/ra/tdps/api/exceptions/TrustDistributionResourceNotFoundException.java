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
package com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions;

import javax.ejb.ApplicationException;

/**
 * This is an API level exception which is thrown to the Rest service in case the URL provided is not found
 * 
 * @author tcsdemi
 *
 */
@ApplicationException(rollback = true)
public class TrustDistributionResourceNotFoundException extends RuntimeException {

    private static final long serialVersionUID = 6420987373248451654L;

    /**
     * Constructs a new TrustDistributionResourceNotFoundException
     */
    public TrustDistributionResourceNotFoundException() {
        super();
    }

    /**
     * Constructs a new TrustDistributionResourceNotFoundException with message
     * 
     * @param message
     *            The detailed message
     */
    public TrustDistributionResourceNotFoundException(final String message) {
        super(message);
    }

    /**
     * Constructs a new TrustDistributionResourceNotFoundException with message and cause
     * 
     * @param message
     *            The detailed message
     * @param cause
     *            the cause which is used for later retrieval
     */
    public TrustDistributionResourceNotFoundException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new TrustDistributionResourceNotFoundException with cause
     * 
     * @param cause
     *            the cause which is used for later retrieval
     */
    public TrustDistributionResourceNotFoundException(final Throwable cause) {
        super(cause);
    }
}
