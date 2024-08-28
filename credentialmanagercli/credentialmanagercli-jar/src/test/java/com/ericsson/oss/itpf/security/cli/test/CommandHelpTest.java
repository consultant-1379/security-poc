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
package com.ericsson.oss.itpf.security.cli.test;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credentialmanager.cli.api.Command.COMMAND_TYPE;
import com.ericsson.oss.itpf.security.credentialmanager.cli.implementation.CommandHelp;

public class CommandHelpTest {

    @Test
    public void test() {
        
        final CommandHelp help = new CommandHelp();
        
        final int result = help.execute();
        assertTrue("help.execute", result == 0);
        
        final String result2 = help.getHelpMessage();
        assertTrue("help.getHelpMessage", result2.contains("Usage"));
        
        final COMMAND_TYPE result3 = help.getType();
        assertTrue("help.getType", result3.equals(COMMAND_TYPE.HELP));
        
        final List<String> result4 = help.getValidArguments();       
        assertFalse("help.getValidArguments", result4.isEmpty());
        assertTrue("help.getValidArguments", result4.get(0).contains("-h"));
    }

}
