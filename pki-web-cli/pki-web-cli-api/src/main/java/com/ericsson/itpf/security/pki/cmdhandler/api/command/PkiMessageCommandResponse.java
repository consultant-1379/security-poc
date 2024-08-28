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

/**
 * <p>
 * A subclass of PkiCommandResponse representing a Message response as result of a com.ericsson.itpf.security.pki.command execution
 * </p>
 *
 * @author xsumnan on 29/03/2015.
 */
public class PkiMessageCommandResponse extends PkiCommandResponse {

    private static final long serialVersionUID = -3681672091985814412L;

    private int errorCode;
    private String message;
    private String suggestedSolution;
    private String errorMessage;

    public PkiMessageCommandResponse() {
    }

    public PkiMessageCommandResponse(final String message) {
        this.message = message;
        this.suggestedSolution = "";
    }

    public PkiMessageCommandResponse(final String message, final String suggestedSolution) {
        this.message = message;
        this.suggestedSolution = suggestedSolution;
    }

	public PkiMessageCommandResponse(final int errorCode, final String errorMessage, final String suggestedSolution) {
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
        this.suggestedSolution = suggestedSolution;
    }

    public PkiMessageCommandResponse(final String message, final int errorCode, final String errorMessage, final String suggestedSolution) {
        this.message = message;
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
        this.suggestedSolution = suggestedSolution;
    }

    /**
     * @return the response message.
     */
    public String getMessage() {
        return message;
    }

    /**
     * Sets the response message.
     *
     * @param message
     *            the response message
     */
    public void setMessage(final String message) {
        this.message = message;
    }

    /**
     * @return the response message.
     */
    public String getSuggestedSolution() {
        return suggestedSolution;
    }

    /**
     * Sets the response message.
     *
     * @param message
     *            the response message
     */
    public void setSuggestedSolution(final String message) {
        this.suggestedSolution = message;
    }

    /**
     * @return the errorCode
     */
    public int getErrorCode() {
        return errorCode;
    }

    /**
     * @param errorCode
     *            the errorCode to set
     */
    public void setErrorCode(final int errorCode) {
        this.errorCode = errorCode;
    }

    /**
     * @return the errorMessage
     */
    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * @param errorMessage
     *            the errorMessage to set
     */
    public void setErrorMessage(final String errorMessage) {
        this.errorMessage = errorMessage;
    }

    /**
     * Always returns PkiCommandResponseType.MESSAGE
     *
     * @return PkiCommandResponseType.MESSAGE
     */
    @Override
    public PKICommandResponseType getResponseType() {
        return PKICommandResponseType.MESSAGE;
    }
}
