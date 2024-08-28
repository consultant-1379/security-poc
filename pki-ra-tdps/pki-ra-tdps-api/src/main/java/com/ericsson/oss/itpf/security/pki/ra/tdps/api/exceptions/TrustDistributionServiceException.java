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
package com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions;

import javax.ejb.ApplicationException;

/**
 * This exception is an API level which is thrown whenever there is any internal application level exception which can be thrown to REST
 * 
 * @author xchowja
 *
 */
@ApplicationException(rollback = true)
public class TrustDistributionServiceException extends RuntimeException {

    private static final long serialVersionUID = 3738822561727915133L;

    /**
     * Constructs a new TrustDistributionServiceException
     */
    public TrustDistributionServiceException() {
        super();
    }

    /**
     * Constructs a new TrustDistributionServiceException with message
     * 
     * @param message
     *            The detailed message
     */
    public TrustDistributionServiceException(final String message) {
        super(message);
    }

    /**
     * Constructs a new TrustDistributionServiceException with message and cause
     * 
     * @param message
     *            The detailed message
     * @param cause
     *            the cause which is used for later retrieval
     */
    public TrustDistributionServiceException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new TrustDistributionServiceException with cause
     * 
     * @param cause
     *            the cause which is used for later retrieval
     */
    public TrustDistributionServiceException(final Throwable cause) {
        super(cause);
    }

}
