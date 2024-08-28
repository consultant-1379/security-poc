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

import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException;
import java.io.Serializable;

/**
 * Abstract class representing the result of a com.ericsson.itpf.security.pki.cmdhandler.command execution.
 * <P>
 * Ideally there will be a subclass of this class for each data-structure that needs to be returned as a result of a com.ericsson.itpf.security.pki.cmdhandler.command execution.
 * </P>
 * 
 * 
 * @author xsumnan on 29/03/2015.
 */
public abstract class PkiCommandResponse implements Serializable {

    private static final long serialVersionUID = -4509415053579546437L;

    /**
     * Method to get the response type of the instance
     * 
     * @return the response type represented by this instance
     */
    public abstract PKICommandResponseType getResponseType();

    /**
     * Convenience method to create a PkiMessageCommandResponse
     * 
     * @param message
     *            String with the message to be return to client
     * @return PkiMessageCommandResponse with the provided message
     */
    public static PkiMessageCommandResponse message(final String message) {
        return new PkiMessageCommandResponse(message);
    }
	/**
     * Convenience method to create a PkiMessageCommandResponse
     * 
     * @param errorCode
     *            errorCode representing the errorMessage
     * @param errorMessage
     *            String with the errorMessage to be return to client
     * @param suggestedSolution
     *            String with the suggested Solution to be return to client
     * @return PkiMessageCommandResponse with the provided message
     */
    public static PkiMessageCommandResponse message(final int errorCode, final String errorMessage, final String suggestedSolution) {

        final PkiMessageCommandResponse pkiMessageCommandResponse = new PkiMessageCommandResponse(PkiWebCliException.ERROR_CODE_START_INT + errorCode, errorMessage, suggestedSolution);
        pkiMessageCommandResponse.setMessage("Error: " + (PkiWebCliException.ERROR_CODE_START_INT + errorCode) + " " + errorMessage);

        return pkiMessageCommandResponse;
    }

    /**
     * Convenience method to create a PkiMessageCommandResponse
     * 
     * @param message
     *            String with the message to be return to client
     * @param suggestedSolution
     *            String with the suggested Solution to be return to client
     * @return PkiMessageCommandResponse with the provided message
     */
    public static PkiMessageCommandResponse message(final String message, final String suggestedSolution) {
        return new PkiMessageCommandResponse(message, suggestedSolution);
    }

    /**
     * Convenience method to create a PkiNameValueCommandResponse
     * 
     * @return PkiNameValueCommandResponse
     */
    public static PkiNameValueCommandResponse nameValue() {
        return new PkiNameValueCommandResponse();
    }

    /**
     * Convenience method to create a PkiNameMultipleValueCommandResponse
     * 
     * @return PkiNameMultipleValueCommandResponse
     */
    public static PkiNameMultipleValueCommandResponse nameMultipleValue(final int numberOfCoulmns) {
        return new PkiNameMultipleValueCommandResponse(numberOfCoulmns);
    }

    /**
     * Auxiliary method to check if this PkiCommandResponse is of PkiNameValueCommandResponse type
     * 
     * @return true - if getResponseType() == PkiCommandResponseType.NAME_VALUE
     */
    public boolean isNameValueResponseType() {
        return PKICommandResponseType.NAME_VALUE.equals(getResponseType());
    }

    /**
     * Auxiliary method to check if this PkiCommandResponse is of PkiNameMultipleValueCommandResponse type
     * 
     * @return true - if getResponseType() == PkiCommandResponseType.NAME_MULTIPLE_VALUE
     */
    public boolean isNameMultipleValueResponseType() {
        return PKICommandResponseType.NAME_MULTIPLE_VALUE.equals(getResponseType());
    }

    /**
     * Auxiliary method to check if this PkiCommandResponse is of PkiNameMultipleValueAndTableCommandResponse type
     * 
     * @return true - if getResponseType() == PkiCommandResponseType.NAME_MULTIPLE_VALUE_AND_TABLE
     */
    public boolean isNameMultipleValueAndTableResponseType() {
        return PKICommandResponseType.NAME_MULTIPLE_VALUE_AND_TABLE.equals(getResponseType());
    }

    /**
     * Auxiliary method to check if this PkiCommandResponse is of PkiMessageCommandResponse type
     * 
     * @return true - if getResponseType() == PkiCommandResponseType.MESSAGE
     */
    public boolean isMessageResponseType() {
        return PKICommandResponseType.MESSAGE.equals(getResponseType());
    }

    /**
     * Auxiliary method to check if this PkiCommandResponse is of PkiMessageCommandResponse type
     * 
     * @return true - if getResponseType() == PkiDownloadRequestToScriptEngine.MESSAGE
     */
    public boolean isDownloadRequestType() {
        return PKICommandResponseType.DOWNLOAD_REQ.equals(getResponseType());
    }

    /**
     * @return
     */
    public boolean isMessageMultipleValueType() {
        return PKICommandResponseType.MESSAGE_MULTIPLE_VALUE.equals(getResponseType());
    }

    /**
     * Auxiliary method to check if this PkiCommandResponse is of PkiDownloadRequestMessageCommandResponse type
     * 
     * @return true - if getResponseType() == PkiDownloadRequestMessageCommandResponse.DOWNLOAD_REQ_MESSAGE
     */
    public boolean isDownloadRequestMessageType() {
        return PKICommandResponseType.DOWNLOAD_REQ_MESSAGE.equals(getResponseType());
    }

    /**
     * Enumeration of the possibles PKI response types
     */
    public enum PKICommandResponseType {
        MESSAGE, NAME_VALUE, NAME_MULTIPLE_VALUE, DOWNLOAD_REQ, MESSAGE_MULTIPLE_VALUE, DOWNLOAD_REQ_MESSAGE, NAME_MULTIPLE_VALUE_AND_TABLE;
    }
}
