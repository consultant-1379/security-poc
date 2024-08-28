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
 * UnauthorizedException will be thrown in following scenarios: 1)When the OTPValidation fails. 2)Entity not found for which the certificate has to be created. 3)Invalid Entity arguments are fetched
 * for the provided entity for certificate generation.
 *
 * @author xananer
 */
public class UnauthorizedException extends ProtocolException {
    /**
     *
     */
    private static final long serialVersionUID = 1L;

    /**
     * @param msg
     *            is the description of the exception
     */
    public UnauthorizedException(final String msg) {
        super(msg);
    }
}