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

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCliCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.CommandSyntaxException;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;

@RunWith(MockitoJUnitRunner.class)
public class AntlrCommandParserTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(AntlrCommandParser.class);

    @InjectMocks
    AntlrCommandParser antlrCommandParser;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(antlrCommandParser);
    }

    @Test
    public void testParseCommandSuccess() {
        PkiCliCommand cliCommand = new PkiCliCommand("cfg algo -l -t all -s all");
        AntlrCommandParser antlrCommandParser = new AntlrCommandParser();
        PkiPropertyCommand pkiPropertyCommand = antlrCommandParser.parseCommand(cliCommand);
        assertEquals(pkiPropertyCommand.getCommandType(), PkiCommandType.CONFIGMGMTLIST);
    }

    @Test(expected = CommandSyntaxException.class)
    public void testParseCommandFailure() {
        MockitoAnnotations.initMocks(antlrCommandParser);
        PkiCliCommand cliCommand = new PkiCliCommand("cfg algorithm -list --type dh --status all ");
        PkiPropertyCommand pkiPropertyCommand = antlrCommandParser.parseCommand(cliCommand);
        assertEquals(pkiPropertyCommand.getCommandType(), PkiCommandType.CONFIGMGMTLIST);
    }

}
