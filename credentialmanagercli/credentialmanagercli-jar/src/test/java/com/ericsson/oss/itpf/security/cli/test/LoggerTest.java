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

import com.ericsson.oss.itpf.security.credentialmanager.cli.util.Logger;
import org.apache.commons.cli.ParseException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import javax.naming.NamingException;
import java.io.IOException;

import static org.junit.Assert.assertTrue;

@RunWith(JUnit4.class)
public class LoggerTest {

    @Test
    public void testDefaultLogger() throws NamingException, ParseException, IOException {

        // TORF-562254 update log4j
        org.apache.logging.log4j.Logger LOG = Logger.getLogger();

        
        LOG.debug("test");
        LOG.debug("test", new Object());
        LOG.debug("test",null, null);
        LOG.info("test");
        LOG.info("test", new Object());
        LOG.info("test", null, null);
        LOG.error("test");
        LOG.error("test",  new Object());
        LOG.error("test", null, null);
        LOG.warn("test");
        LOG.warn("test", new Object());
        LOG.warn("test", null, null);
        LOG.trace("test");
        LOG.trace("test", new Object());
        LOG.trace("test", null, null);
        
        LOG.getName();
        LOG.isDebugEnabled();
        LOG.isErrorEnabled();
        LOG.isInfoEnabled();
        LOG.isTraceEnabled();
        LOG.isWarnEnabled();
        LOG.isDebugEnabled(null);
        LOG.isErrorEnabled(null);
        LOG.isInfoEnabled(null);
        LOG.isTraceEnabled(null);
        LOG.isWarnEnabled(null);
        
        assertTrue("log not null", LOG != null);

        org.apache.logging.log4j.Logger DefLog = Logger.getDefaultLogger();
        assertTrue("default log not null", DefLog != null);

        // check messagged
	final String messok = com.ericsson.oss.itpf.security.credentialmanager.cli.util.Logger.getLogMessage(Logger.LOG_DEBUG_START_APP);
        assertTrue("getLogMessageTest ok", messok != null);
        final String messnok = com.ericsson.oss.itpf.security.credentialmanager.cli.util.Logger.getLogMessage("xxxxxx");
        assertTrue("getLogMessageTest nok", messnok == null);
        
    }
}
