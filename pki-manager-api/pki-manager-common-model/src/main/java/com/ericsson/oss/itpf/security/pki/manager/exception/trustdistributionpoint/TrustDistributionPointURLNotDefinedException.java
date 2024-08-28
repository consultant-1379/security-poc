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
package com.ericsson.oss.itpf.security.pki.manager.exception.trustdistributionpoint;

import com.ericsson.oss.itpf.security.pki.manager.exception.TrustDistributionPointException;

/**
 * This exception is thrown when TrustDistribution publish flag is not set.
 * 
 * @author tcsramc
 *
 */
public class TrustDistributionPointURLNotDefinedException extends TrustDistributionPointException {

    private static final long serialVersionUID = -1485356747463022543L;

    /**
     * Constructs a new TrustDistributionPointURLNotDefinedException
     */
    public TrustDistributionPointURLNotDefinedException() {
        super();
    }

    /**
     * Constructs a new TrustDistributionPointURLNotDefinedException with
     * detailed message
     * 
     * @param message
     *            the detailed message. The detail message is saved for later
     *            retrieval by the {@link #getMessage()} method.
     */

    public TrustDistributionPointURLNotDefinedException(final String message) {
        super(message);
    }

    /**
     * Constructs a new TrustDistributionPointURLNotDefinedException with cause
     * 
     * @param cause
     *            the cause (which is saved for later retrieval by the
     *            {@link #getCause()} method)
     */

    public TrustDistributionPointURLNotDefinedException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new TrustDistributionPointURLNotDefinedException with
     * detailed message and cause
     * 
     * @param message
     *            the detailed message (which is saved for later retrieval by
     *            the {@link #getMessage()} method).
     * @param cause
     *            the cause (which is saved for later retrieval by the
     *            {@link #getCause()} method)
     */

    public TrustDistributionPointURLNotDefinedException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
