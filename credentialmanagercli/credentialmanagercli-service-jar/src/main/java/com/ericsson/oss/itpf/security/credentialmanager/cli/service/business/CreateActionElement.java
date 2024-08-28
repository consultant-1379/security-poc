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


import java.util.*;

import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.CheckResult;

public class CreateActionElement {

    public static List<Actions> parseActionList(final CheckResult result, final List<CredentialManagerCheckAction> actionlist) {
        
        final List<Actions> parseOutput = new ArrayList<Actions>();

        if (!result.isAllFalse()) {
            final Iterator<CredentialManagerCheckAction> checkActionIterator = actionlist.iterator();
            while (checkActionIterator.hasNext()) {
                final CredentialManagerCheckAction currentCheckAction = checkActionIterator.next();
                final List<CredentialManagerActionCauseEnum> causes = currentCheckAction.getCheckcause();
                final Iterator<CredentialManagerActionCauseEnum> actionCauseIterator = causes.iterator();
                while (actionCauseIterator.hasNext()) {
                    if (result.getResult(actionCauseIterator.next().toString())) {
                        final CredentialManagerActionEnum action = currentCheckAction.getAction();
                        final CredentialManagerCommandType comand = currentCheckAction.getCommand();
                        final Actions elementAction = new Actions();
                        elementAction.setAction(action);
                        elementAction.setCommand(comand);
                        if (!parseOutput.contains(elementAction)) {
                            parseOutput.add(elementAction);
                        }
                        break;
                    }
                }
            }
        }
        return parseOutput;
    }
}
