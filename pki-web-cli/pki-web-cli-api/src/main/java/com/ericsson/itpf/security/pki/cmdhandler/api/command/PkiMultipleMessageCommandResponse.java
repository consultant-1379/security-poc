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
package com.ericsson.itpf.security.pki.cmdhandler.api.command;

import java.util.List;

public class PkiMultipleMessageCommandResponse extends PkiCommandResponse {

	/**
     * 
     */
	private static final long serialVersionUID = -1164632722700612579L;

	private List<String> message;

	/**
	 * Constructor for creating an instance for
	 * PkiMultipleMessageCommandResponse
	 * 
	 * @param message
	 */
	public PkiMultipleMessageCommandResponse() {
	}

	/**
	 * Constructor for creating an instance for
	 * PkiMultipleMessageCommandResponse
	 * 
	 * @param message
	 */
	public PkiMultipleMessageCommandResponse(final List<String> message) {
		this.message = message;
	}

	/**
	 * @return the response message.
	 */
	public List<String> getMessage() {
		return message;
	}

	/**
	 * Sets the response message.
	 * 
	 * @param message
	 *            the response message
	 */
	public void setMessage(final List<String> message) {
		this.message = message;
	}

	/**
	 * Always returns PkiCommandResponseType.MESSAGE
	 * 
	 * @return PkiCommandResponseType.MESSAGE
	 */
	@Override
	public PKICommandResponseType getResponseType() {
		return PKICommandResponseType.MESSAGE_MULTIPLE_VALUE;
	}

}
