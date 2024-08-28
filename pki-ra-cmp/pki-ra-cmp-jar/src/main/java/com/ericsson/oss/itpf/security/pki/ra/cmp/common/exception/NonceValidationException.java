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
 * This exception is thrown when nonce validation fails
 * 
 * @author tcsdemi
 *
 */
public class NonceValidationException extends ValidationException {

    private static final long serialVersionUID = 605516226093051207L;

    /**
     * This exception is thrown when Nonce validation fails.
     * 
     * @param errorMessage
     *            This is a user defined errorMessage
     */
    public NonceValidationException(final String errorMessage) {
        super(errorMessage);
    }

}
