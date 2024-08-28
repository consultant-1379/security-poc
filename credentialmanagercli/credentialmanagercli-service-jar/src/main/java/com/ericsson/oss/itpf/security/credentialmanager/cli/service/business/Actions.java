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
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.business;

import java.util.Iterator;

import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerActionEnum;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerCommandType;


public class Actions {

    CredentialManagerActionEnum action;
    CredentialManagerCommandType command;

    /**
     * @return the action
     */
    public CredentialManagerActionEnum getAction() {
        return this.action;
    }

    /**
     * @param action
     *            the action to set
     */
    public void setAction(final CredentialManagerActionEnum action) {
        this.action = action;
    }

    /**
     * @return the command
     */
    public CredentialManagerCommandType getCommand() {
        return this.command;
    }

    /**
     * @param command
     *            the command to set
     */
    public void setCommand(final CredentialManagerCommandType command) {
        this.command = command;
    }

    @Override
    public boolean equals(final Object obj) {

        if (this == obj) {
            return true;
        }

        if (obj == null || this.getClass() != obj.getClass()) {
            return false;
        }

        final Actions other = (Actions) obj;
        if(this.action != null) {
            if (!this.action.equals(other.action)) {
                return false;
            }
        }
        else {
            if(other.action != null) {
                return false;
            }
        }

        if (this.command != null && other.command != null) {
            //it will not check null command fields because CredentialManagerCommandType instantiate them inside its constructor
            if (this.command.getPathname().size() != other.command.getPathname().size()) {
                return false;
            }

            final Iterator<String> iter = this.command.getPathname().iterator();
            final Iterator<String> otheriter = other.command.getPathname().iterator();
            while (iter.hasNext()) {
                otheriter.hasNext();
                if (!iter.next().contentEquals(otheriter.next())) {
                    return false;
                }
            }

            if (this.command.getParameterName().size() != other.command.getParameterName().size()) {
                return false;
            }

            final int size = this.command.getParameterName().size(); //beacause of xsd the parameter size is the same of value size
            for (int i=0; i<size; i++) {
                if ( !this.command.getParameterName().get(i).equals(other.command.getParameterName().get(0))) {
                    return false;
                }
                if ( !this.command.getParameterValue().get(i).equals(other.command.getParameterValue().get(0))) {
                    return false;
                }
            }


        } else if (this.command == null ^ other.command == null) {
            return false;
        }
        return true;
    }
    
}  // end of Actions
