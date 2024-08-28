/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
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
 * A subclass of PkiCommandResponse representing the download request to script-engine Should be used in case of any file download request needs to be sent to script-engine and also Message response
 * as result of a com.ericsson.itpf.security.pki.command execution
 * 
 * @author xgvgvgv
 * 
 */
public class PkiDownloadRequestMessageCommandResponse extends PkiCommandResponse {

    private static final long serialVersionUID = 1L;
    private String fileIdentifier = null;
    private String message;

    public PkiDownloadRequestMessageCommandResponse() {
    }

    public PkiDownloadRequestMessageCommandResponse(final String fileIdentifier, final String message) {
        this.fileIdentifier = fileIdentifier;
        this.message = message;
    }

    @Override
    public PKICommandResponseType getResponseType() {
        return PKICommandResponseType.DOWNLOAD_REQ_MESSAGE;
    }

    /**
     * Unique key used by webcli to store file in memory
     * 
     * @return
     */
    public String getFileIdentifier() {
        return fileIdentifier;
    }

    public void setFileIdentifier(final String fileId) {
        this.fileIdentifier = fileId;
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

}
