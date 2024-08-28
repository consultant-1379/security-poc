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
package com.ericsson.oss.itpf.security.credentialmanager.cli.business;

import com.ericsson.oss.itpf.security.credentialmanager.cli.api.ExecuteCommands;
import com.ericsson.oss.itpf.security.credentialmanager.cli.api.Command;
import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.implementation.CommandParserImpl;

/**
 * 
 * @author ewagdeb
 *         Class responsable to call the command parser and execute the command
 *         implementation
 * 
 */
public class ExecuteCommandsImpl implements ExecuteCommands {

    @Override
    public int execute(final String[] commands) {
        try {

            final Command commandToBeExecuted = new CommandParserImpl().parse(commands);

            return commandToBeExecuted.execute();

        } catch (final Exception e) {
            throw new CredentialManagerException(e);
        }
    }
}
