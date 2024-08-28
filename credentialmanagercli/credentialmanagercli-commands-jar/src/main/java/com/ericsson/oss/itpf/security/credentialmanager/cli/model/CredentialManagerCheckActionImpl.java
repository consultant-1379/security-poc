/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credentialmanager.cli.model;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.CheckActionType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerActionCauseEnum;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerActionEnum;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerCheckAction;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerCommandType;

/**
 * 
 * Hold the KeyStore that comes from XMLBeans generated based on the XSD for credential manager
 * 
 */
public class CredentialManagerCheckActionImpl implements CredentialManagerCheckAction {
    /**
     * 
     */
    private static final long serialVersionUID = 8547613804436273509L;

    List<CredentialManagerActionCauseEnum> checkcause;
    CredentialManagerActionEnum action;
    CredentialManagerCommandType command;;

    public CredentialManagerCheckActionImpl(final Object checkActionObj) {

        CheckActionType checkActionType;

        if (checkActionObj != null && checkActionObj instanceof CheckActionType) {
            checkActionType = (CheckActionType) checkActionObj;
        } else {
            throw new CredentialManagerException("Loading information of checkaction...[Failed]");
        }

        this.setCheckCauseCostr(checkActionType);
        this.setActionCostr(checkActionType);
        this.setCommandCostr(checkActionType);

    }

    /**
     * @param keyStore
     */
    private void setCheckCauseCostr(final CheckActionType checkActionType) {
        if (checkActionType.getCheckcause() != null) {
            this.checkcause = new ArrayList<CredentialManagerActionCauseEnum>();
            final int size = checkActionType.getCheckcause().size();
            for (int i=0; i<size; i++) {
                this.checkcause.add(CredentialManagerActionCauseEnum.valueOf(checkActionType.getCheckcause().get(i).toString()));
            }
        }

    }

    /**
     * @param keyStore
     */
    private void setActionCostr(final CheckActionType checkActionType) {
        if (checkActionType.getAction() != null) {
            this.setAction(CredentialManagerActionEnum.valueOf(checkActionType.getAction().toString()));
        }
    }

    /**
     * @param keyStore
     */
    private void setCommandCostr(final CheckActionType checkActionType) {
        if (checkActionType.getCommand() != null) {
            final CredentialManagerPostScriptCallerImpl commandConverter = new CredentialManagerPostScriptCallerImpl();
            commandConverter.importPostScriptCmd(checkActionType.getCommand());
            this.setCommand(commandConverter.getPostScriptCmd());
        }
    }

    /**
     * @return the checkcause
     */
    @Override
    public List<CredentialManagerActionCauseEnum> getCheckcause() {
        return this.checkcause;
    }
    
    /**
     * @return the action
     */
    @Override
    public CredentialManagerActionEnum getAction() {
        return this.action;
    }

    /**
     * @param action
     *            the action to set
     */
    private void setAction(final CredentialManagerActionEnum action) {
        this.action = action;
    }

    /**
     * @return the command
     */
    @Override
    public CredentialManagerCommandType getCommand() {
        return this.command;
    }

    /**
     * @param command
     *            the command to set
     */
    private void setCommand(final CredentialManagerCommandType command) {
        this.command = command;
    }

} // end of CredentialManagerKeyStoreImpl
