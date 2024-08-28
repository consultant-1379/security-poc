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
package com.ericsson.oss.itpf.security.credmservice.exceptions;

public class CredentialManagerStorageException extends Exception {
	
	private static final long serialVersionUID = 1L;

	/**
	 * 
	 */
	public CredentialManagerStorageException() {
		
	}

	/**
	 * @param message
	 */
	public CredentialManagerStorageException(final String message) {
		super(message);
		
	}

	/**
	 * @param cause
	 */
	public CredentialManagerStorageException(final Throwable cause) {
		super(cause);
		
	}

	/**
	 * @param message
	 * @param cause
	 */
	public CredentialManagerStorageException(final String message, final Throwable cause) {
		super(message, cause);
		
	}

	

}
