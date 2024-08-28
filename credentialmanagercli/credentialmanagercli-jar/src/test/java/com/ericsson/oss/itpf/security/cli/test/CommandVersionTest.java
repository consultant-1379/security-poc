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
import com.ericsson.oss.itpf.security.credentialmanager.cli.implementation.CommandVersion;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CommandVersionTest {

    @Test
    public void test() {
        
        final CommandVersion version = new CommandVersion();
        
        final int result = version.execute();
        assertTrue("version.execute", result == 0);
        
        final COMMAND_TYPE result3 = version.getType();
        assertTrue("version.getType", result3.equals(COMMAND_TYPE.VERSION));
        
        final List<String> result4 = version.getValidArguments();       
        assertFalse("version.getValidArguments", result4.isEmpty());
        assertTrue("version.getValidArguments", result4.get(0).contains("-v"));
    }

}
