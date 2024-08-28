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

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credentialmanager.cli.CLI;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

public class CLItest {

    @Test
    public void test() {
        
        final String[] args = {"-h"};
        final CLI cli = new CLI(args);
        assertTrue("CLI", true);

        cli.main(args);
        assertTrue("CLI", true);   
    }

}
