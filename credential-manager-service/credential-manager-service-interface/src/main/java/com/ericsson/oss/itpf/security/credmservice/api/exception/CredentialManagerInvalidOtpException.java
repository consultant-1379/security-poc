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

public class CredentialManagerInvalidOtpException extends CredentialManagerServiceException {

	private static final long serialVersionUID = 4358731042861524216L;

	/**
     * 
     */
    public CredentialManagerInvalidOtpException() {
        super(CredentialManagerErrorCodes.OTP_INVALID);
    }

    /**
     * @param errorMessage
     */
    public CredentialManagerInvalidOtpException(String errorMessage) {
        super(formatMessage(CredentialManagerErrorCodes.OTP_INVALID, errorMessage));
    }

    /**
     * @param errorMessage
     * @param cause
     */
    public CredentialManagerInvalidOtpException(String errorMessage, Throwable cause) {
        super(formatMessage(CredentialManagerErrorCodes.OTP_INVALID, errorMessage), cause);
    }

}
