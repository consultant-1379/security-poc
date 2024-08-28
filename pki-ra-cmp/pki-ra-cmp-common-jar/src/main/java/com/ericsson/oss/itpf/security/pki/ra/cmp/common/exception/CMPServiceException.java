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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception;

import com.ericsson.oss.itpf.security.pki.common.exception.ProtocolException;

/**
 * This Exception will be thrown when an exception occurs while fetching configuration parameter for DBCleanup
 * 
 * @author tcsramc
 * 
 */
public class CMPServiceException extends ProtocolException {

    private static final long serialVersionUID = 1L;

    /**
     * This Exception will be thrown when an exception occurs while fetching configuration parameter for DBCleanup
     * 
     * @param errorMessage
     *            error message which user sets.
     */
    public CMPServiceException(final String errorMessage) {
        super(errorMessage);
    }

    public CMPServiceException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }
}
