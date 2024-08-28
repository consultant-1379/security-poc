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

import com.ericsson.oss.itpf.security.pki.common.exception.ValidationException;

/**
 * This exception is thrown when header within RequestMessage contains invalid
 * version or invalid name format
 */
public class HeaderValidationException extends ValidationException {

    private static final long serialVersionUID = -3478795753431235433L;

    /**
     * This exception is thrown when header within RequestMessage contains
     * invalid version or invalid name format
     * 
     * @param errorMessage
     *            It can be user defined error message like "Invalid version"
     */
    public HeaderValidationException(final String errorMessage) {
        super(errorMessage);
    }

}
