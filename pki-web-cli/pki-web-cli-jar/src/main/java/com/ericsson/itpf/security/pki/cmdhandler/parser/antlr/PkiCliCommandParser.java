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

package com.ericsson.itpf.security.pki.cmdhandler.parser.antlr;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCliCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.CommandSyntaxException;

/**
 * Base Interface for parser
 * 
 * @author xsumnan on 29/03/2015.
 */
public interface PkiCliCommandParser {

    /**
     * Perform parsing of the com.ericsson.itpf.security.pki.command.
     * 
     * @param com
     *            .ericsson.itpf.security.pki.command PkiCliCommand with the com.ericsson.itpf.security.pki.command text in it
     * @return translated PkiPropertyCommand instance
     * @throws CommandSyntaxException
     *             when the input command is not aligned to grammar for the command
     */
    PkiPropertyCommand parseCommand(PkiCliCommand command) throws CommandSyntaxException;
}