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

public class ConfigurationException extends Exception {


        private static final long serialVersionUID = 735131463593541434L;

        /**
	 * 
	 */
	public ConfigurationException() {

	}

	/**
	 * @param message
	 */
	public ConfigurationException(final String message) {
		super("credential-manager-service-api: issueCertificate: " + message);

	}

	/**
	 * @param cause
	 */
	public ConfigurationException(final Throwable cause) {
		super(cause);

	}

	/**
	 * @param message
	 * @param cause
	 */
	public ConfigurationException(final String message, final Throwable cause) {
		super("credential-manager-service-api: issueCertificate: " + message,
				cause);

	}

}
