/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.api.exception;

public class CredentialManagerOtpExpiredException extends CredentialManagerServiceException {

    private static final long serialVersionUID = 8099045318279618139L;

    /**
     * 
     */
    public CredentialManagerOtpExpiredException() {
        super(CredentialManagerErrorCodes.OTP_EXPIRED);
    }

    /**
     * @param errorMessage
     */
    public CredentialManagerOtpExpiredException(String errorMessage) {
        super(formatMessage(CredentialManagerErrorCodes.OTP_EXPIRED, errorMessage));
    }

    /**
     * @param errorMessage
     * @param cause
     */
    public CredentialManagerOtpExpiredException(String errorMessage, Throwable cause) {
        super(formatMessage(CredentialManagerErrorCodes.OTP_EXPIRED, errorMessage), cause);
    }
    
    /**
     * @param cause
     */
    public CredentialManagerOtpExpiredException(final Throwable cause) {
        super(CredentialManagerErrorCodes.OTP_EXPIRED, cause);
    }

}
