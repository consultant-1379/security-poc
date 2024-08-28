/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
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
 * This exception is thrown when algorithms used are not supported by the
 * PKISystem.
 *
 * @author tcsdemi
 *
 */
public class UnsupportedAlgorithmException extends ValidationException {

    private static final long serialVersionUID = 605516226093051207L;

    /**
     * This exception is thrown when algorithms used are not supported by the
     * PKISystem.
     * 
     * @param errorMessage
     *            This is user defined error message
     */
    public UnsupportedAlgorithmException(final String errorMessage) {
        super(errorMessage);
    }



}