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
package com.ericsson.oss.itpf.security.credmservice.ejb.startup;

import java.util.Date;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.LocalBean;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerConfig;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerStartupException;

import com.ericsson.oss.itpf.security.credmservice.util.FileUtils;

@LocalBean
@Stateless
public class CredMServiceSPSCredentials {

    public static final long TIMEOUT = 40000L;
    private static final Logger log = LoggerFactory.getLogger(CredMServiceSPSCredentials.class);

    private static final String JBOSS_ACTION_RESTART_LOCK_FILE = "/ericsson/credm/service/removetojbossrestart.lock";

    @EJB
    CredMServiceBeanProxy proxy;

    

    @Resource
    private SessionContext ctx;

    /**
     * Schedule the single action timer
     *
     * @param timeout
     */
    public void scheduleTimerForSPSCredentials(final long timeout) {
        log.info("Scheduling single action timer for generate SPS Jboss credentials");
        final TimerConfig config = new TimerConfig();
        config.setInfo("Executing single action timer for generate SPS Jboss credentials");
        config.setPersistent(false);
        ctx.getTimerService().createSingleActionTimer(new Date(new Date().getTime() + timeout), config);
    }

    /**
     * this handles the CredM service startup procedure part that creates the Jboss SPS credentials for the secure EJB to EJB communication. After
     * that, it reload the jboss instance to activate certificates on EJB connector. If Jboss credentials generation fails, retry after TIMEOUT
     *
     * @param timer
     */
    @Timeout
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void timeoutHandler(final Timer timer) {

        try {
            log.info("Starting SPS credentials generation");
            proxy.generateJBossCredentials();
            log.info("End SPS credentials generation. JBOSS Restarting...");
            FileUtils.delete(JBOSS_ACTION_RESTART_LOCK_FILE);
        } catch (final CredentialManagerStartupException e) {
            log.info("Detected startup procedure problem; retry in " + TIMEOUT + "usec.");
            scheduleTimerForSPSCredentials(TIMEOUT);
        }
    }
}
