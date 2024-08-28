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

public class CredentialManagerInvalidCAException  extends CredentialManagerServiceException  {
	 
	private static final long serialVersionUID = 6802792321368947535L;

		public CredentialManagerInvalidCAException(final String errorMessage, final Throwable cause) {
	        super(formatMessage(CredentialManagerErrorCodes.INVALID_CA, errorMessage), cause);
	    }

	    public CredentialManagerInvalidCAException(final String errorMessage) {
	        super(formatMessage(CredentialManagerErrorCodes.INVALID_CA, errorMessage));
	    }

	    public CredentialManagerInvalidCAException(final Throwable cause) {
	        super(CredentialManagerErrorCodes.INVALID_CA, cause);
	    }

	    public CredentialManagerInvalidCAException() {
	        super(CredentialManagerErrorCodes.INVALID_CA);
	    }

}
