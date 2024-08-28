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
package com.ericsson.oss.itpf.security.credmsapi.api.exceptions;

public class ReIssueLegacyXMLCertificateException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 8840982918905731738L;

	
	public ReIssueLegacyXMLCertificateException() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 */
	public  ReIssueLegacyXMLCertificateException(final String message) {
		super(message);
		
	}

	/**
	 * @param cause
	 */
	public ReIssueLegacyXMLCertificateException(final Throwable cause) {
		super(cause);
		
	}

	/**
	 * @param message
	 * @param cause
	 */
	public ReIssueLegacyXMLCertificateException(final String message, final Throwable cause) {
		super(message, cause);
		
	}

}
