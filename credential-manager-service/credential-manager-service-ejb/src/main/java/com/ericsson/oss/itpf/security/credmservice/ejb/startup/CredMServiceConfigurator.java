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

import java.net.InetAddress;

import javax.ejb.EJB;
import javax.ejb.LocalBean;
import javax.ejb.Schedule;
import javax.ejb.Stateless;
import javax.ejb.Timer;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.inject.Inject;
import javax.management.AttributeNotFoundException;
import javax.management.InstanceNotFoundException;
import javax.management.MBeanException;
import javax.management.MalformedObjectNameException;
import javax.management.ReflectionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.credmservice.api.CredMRestAvailability;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerDbUpgradeException;
import com.ericsson.oss.itpf.security.credmservice.util.FileUtils;
import com.ericsson.oss.itpf.security.credmservice.util.MBeanManager;

@LocalBean
@Stateless
public class CredMServiceConfigurator {

    public static final long TIMEOUT = 5000L;
    private static final Logger log = LoggerFactory.getLogger(CredMServiceConfigurator.class);

    private static final String STARTUP_OK_LOCK_FILE = "/ericsson/credm/service/jbossStartup.lock";
    private static final String SHARED_FILES_LOCATION = "/ericsson/tor/data/credm/hosts/";

    @EJB
    CredMServiceBeanProxy proxy;

    @Inject
    CredMServiceSPSCredentials timerForSPS;

    @Inject
    CredMServiceCheckSPSCredentials timerForSPSCheck;

    @EJB
    CredMRestAvailability credmServiceStartupConfBean;

    @EJB
    private JcaFileResourceBean resourceBean;

    @EServiceRef
    private CredMService credMService;

    /**
     * This handles the CredM service startup procedure. Creates the profiles, CA entities and certificates for the ENM PKI infrastructure CAs. After that, schedule another single action timer that
     * will creates the initial certificates for the CredM Service itself for the secure EJB to EJB communication
     *
     * @param timer
     */
    @Schedule(second = "*/5", minute = "*", hour = "*", persistent = false)
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void timeoutHandler(final Timer timer) {
    	// Check if PKI MANAGER is deployed
    	try {
    		if (!MBeanManager.getPKIManagerDeployed()) {
    			return;
    		}
    	} catch (MalformedObjectNameException | AttributeNotFoundException | InstanceNotFoundException | MBeanException | ReflectionException e) {
            log.info("getPKIManagerDeployed throws declared exception!", e);
            return;
    	} catch (final Exception ex) {
            log.info("getPKIManagerDeployed throws exception!", ex);
            return;
    	}
    	timer.cancel();
    	if (CredMServiceSelfCredentialsManager.checkCertificateValidity()) {
    		log.info("Certificates validity check: OK.");
    		FileUtils.delete(STARTUP_OK_LOCK_FILE);
    		writeSharedFiles();
    		credmServiceStartupConfBean.setRestEnabled(true);
    		timerForSPSCheck.scheduleTimerForCheckSPSCredentials();
    	} else {
    		log.info("Certificates validity check: NOTOK. Start PKI DB Upgrade Procedure.");

    		try {
    			this.proxy.pkiDbUpgrade();

    		} catch (CredentialManagerDbUpgradeException e) {
    			e.printStackTrace();
    			log.error("Ended PKI DB Upgrade Procedure with error reported.");
    			this.proxy.checkDbCvnStatus();
    		}
    	
    		log.info("Ended PKI DB Upgrade Procedure. Scheduling timer for SPS credentials generation");
    		timerForSPS.scheduleTimerForSPSCredentials(1000L);

    	}
    }
        

    public boolean writeSharedFiles() {
        try {
            final String filename = SHARED_FILES_LOCATION  + InetAddress.getLocalHost().getHostName();
            resourceBean.init(filename);
            if (resourceBean.supportsWriteOperations()) {
                final String rowString = "ipv4=" + InetAddress.getLocalHost().getHostAddress() + System.getProperty("line.separator") + "version=" + credMService.getVersion()
                + System.getProperty("line.separator");
                final byte[] row = rowString.getBytes();
                resourceBean.write(row, false);
            }
            return true;
        } catch (final Exception e) {
            log.error("writeSharedFiles throws exception!" + e.getMessage());
            return false;
        }
    }
}
