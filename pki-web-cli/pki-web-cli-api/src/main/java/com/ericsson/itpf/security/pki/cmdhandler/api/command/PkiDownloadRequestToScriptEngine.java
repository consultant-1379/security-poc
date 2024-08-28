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
 * A subclass of PkiCommandResponse representing the download request to script-engine Should be used in case of any file download request needs to be sent to scriptengine
 * 
 * @author xsumnan
 * 
 */
public class PkiDownloadRequestToScriptEngine extends PkiCommandResponse {

    private static final long serialVersionUID = 1L;

    private String fileIdentifier = null;

    @Override
    public PKICommandResponseType getResponseType() {
        return PKICommandResponseType.DOWNLOAD_REQ;
    }

    /**
     * Unique key used by webcli to store file inmemory
     * 
     * @return
     */
    public String getFileIdentifier() {
        return fileIdentifier;
    }

    public void setFileIdentifier(final String fileId) {
        this.fileIdentifier = fileId;
    }

}
