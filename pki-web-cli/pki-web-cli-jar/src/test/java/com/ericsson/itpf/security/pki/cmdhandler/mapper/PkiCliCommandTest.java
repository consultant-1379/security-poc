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

package com.ericsson.itpf.security.pki.cmdhandler.mapper;

import static org.junit.Assert.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCliCommand;

@RunWith(MockitoJUnitRunner.class)
public class PkiCliCommandTest {

    @Test
    public void testConstructor() {
        PkiCliCommand pkiCliCommand = new PkiCliCommand("pkiadm pf --list --profiletype all");
        assertEquals("pkiadm pf --list --profiletype all", pkiCliCommand.getCommandText());
    }

    @Test
    public void testSetCommand() {
        PkiCliCommand pkiCliCommand = new PkiCliCommand();
        pkiCliCommand.setCommandText("pkiadm pf --list --profiletype all");
        assertEquals("pkiadm pf --list --profiletype all", pkiCliCommand.getCommandText());
    }

    @Test
    public void testToString() {
        PkiCliCommand pkiCliCommand = new PkiCliCommand();
        pkiCliCommand.setCommandText("pkiadm pf --list --profiletype all");
        assertEquals("pkiadm pf --list --profiletype all", pkiCliCommand.toString());
    }

}
