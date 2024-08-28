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
package com.ericsson.oss.itpf.security.credentialmanager.cli.model;

import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.CommandType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerCommandType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerPostScriptCaller;

public class CredentialManagerPostScriptCallerImpl implements CredentialManagerPostScriptCaller {

    private CredentialManagerCommandType postScriptCmd;

    /**
     * @return the postScriptCmd
     */
    @Override
    public CredentialManagerCommandType getPostScriptCmd() {
        return this.postScriptCmd;
    }

    /**
     * @param postScriptCmd
     *            the postScriptCmd to set
     */
    @Override
    public void setPostScriptCmd(final CredentialManagerCommandType postScriptCmd) {
        this.postScriptCmd = postScriptCmd;
    }

    /**
     * 
     * @param postScriptCmd
     */
    public void importPostScriptCmd(final CommandType xmlPostScriptCmd) {

        // check input parameter
        if (xmlPostScriptCmd == null) {
            return;
        }

        this.postScriptCmd = new CredentialManagerCommandType();

        // load pathname list
        if (xmlPostScriptCmd.getPathname().isEmpty()) {
            return;
        }

        this.postScriptCmd.setPathname(xmlPostScriptCmd.getPathname());

        // build parameter lists
        if (xmlPostScriptCmd.getParameter() != null) {
            final int size = xmlPostScriptCmd.getParameter().size();
            for (int i = 0; i < size; i++) {
                this.postScriptCmd.addParameterName(xmlPostScriptCmd.getParameter().get(i).getName());
                this.postScriptCmd.addParameterValue(xmlPostScriptCmd.getParameter().get(i).getValue());
            }
        }

    }

}
