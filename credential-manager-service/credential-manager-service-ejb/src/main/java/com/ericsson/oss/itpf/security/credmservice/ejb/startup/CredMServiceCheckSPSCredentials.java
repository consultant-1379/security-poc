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
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.security.credmservice.api.CredMServiceWeb;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringResponse;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringStatus;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerCheckException;
import com.ericsson.oss.itpf.security.credmservice.logging.api.SystemRecorderWrapper;
import com.ericsson.oss.itpf.security.credmservice.util.ApplicationConfiguration;
import com.ericsson.oss.itpf.security.credmservice.util.FileUtils;
import com.ericsson.oss.itpf.security.credmservice.util.PropertiesReader;

@LocalBean
@Stateless
public class CredMServiceCheckSPSCredentials {
    private static final String FILE_PROPERTIES = "/ericsson/credm/service/data/config.properties";
    private static final String CHECK_CREDENTIAL_TIMEOUT = "checkCredentialTimeout";

    private static final String CHECK_CERTS_STATUS_ONTIMEOUT = "checkCertsStatusOnTimeout";
    private static final String FILE_CERTS_PROPERTIES = "/ericsson/tor/data/credm/conf/credentialManagerConfigurator.properties";

    public static final Long TIMEOUT = Long.parseLong(PropertiesReader.getProperties(FILE_PROPERTIES).getProperty(CHECK_CREDENTIAL_TIMEOUT));
    private static final Logger log = LoggerFactory.getLogger(CredMServiceCheckSPSCredentials.class);
    private static final String JBOSS_LOCK_FILE = "/ericsson/credm/service/jbossStartup.lock";

    @EJB
    CredMServiceBeanProxy proxy;

    @EJB
    CredMServiceWeb credMServiceWeb;

    private final String className = this.getClass().getSimpleName();

    @EJB
    private JcaFileResourceBean resourceBean;

    @Resource
    private SessionContext ctx;

    @Inject
    private SystemRecorderWrapper systemRecorder;

    @Inject
    CredMServiceLastMonitoringStatus credMServiceLastMonitoringStatus;

    /**
     * Schedule the single action timer
     *
     * @param timeout
     */
    public void scheduleTimerForCheckSPSCredentials() {
        log.info("Scheduling single action timer for check SPS Jboss credentials ");
        final TimerConfig config = new TimerConfig();
        config.setInfo("Executing single action timer for check SPS Jboss credentials");
        config.setPersistent(false);
        ctx.getTimerService().createSingleActionTimer(new Date(new Date().getTime() + TIMEOUT), config);
    }

    /**
     * this handles the CredM service check Jboss SPS credentials for the secure EJB to EJB communication. If the check reports wrong certificates,
     * the SPS SG has to be undefined and recreated. If Jboss credentials check fails, retry after TIMEOUT.
     */
    @Timeout
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void timeoutHandler(final Timer timer) {

        try {
            log.info("Starting SPS credentials check");
            boolean performCheckSPS = false;

            if (ApplicationConfiguration.isCENM()) {
                final CredentialManagerMonitoringResponse monitoringResp = credMServiceWeb.getMonitoringStatus();
                if (monitoringResp.getHttpStatus() == 200) {
                    credMServiceLastMonitoringStatus.setLastMonitoringStatus(monitoringResp.getMonitoringStatus());
                }
                if (credMServiceLastMonitoringStatus.getLastMonitoringStatus() == CredentialManagerMonitoringStatus.ENABLED) {
                    performCheckSPS = true;
                }
            } else {
                performCheckSPS = checkAndReturnCredentialManagerTimeoutFlag();
            }
            if (performCheckSPS) {
                log.info("Check Certificate Monitoring Status found true, checking now SPS-credentials");
                proxy.checkJBossCredentials();
            } else {
                log.info("Check Certificate Monitoring Status found false, no check on credentials done this time");
                // write to system recorder
                this.systemRecorder.recordEvent("timeoutHandler", EventLevel.DETAILED, className, "scheduleTimerForCheckSPSCredentials ",
                        "Check Certificate Monitoring Status found false, no check on SPS-credentials done this time");
            }
            log.info("End SPS credentials check.");
            scheduleTimerForCheckSPSCredentials();
        } catch (final CredentialManagerCheckException e) {
            this.systemRecorder.recordError("CredentialManagerCheckException", ErrorSeverity.ERROR, className, "Failed check for credentials. Restart VM", e.getMessage());
            writeStateFile();
        }
    }

    public boolean writeStateFile() {
        try {
            final String filename = JBOSS_LOCK_FILE;
            resourceBean.init(filename);
            if (resourceBean.supportsWriteOperations()) {
                final String rowString = "Restart server";
                final byte[] row = rowString.getBytes();
                resourceBean.write(row, false);
            }
            return true;
        } catch (final Exception e) {
            log.error("writeStateFile throws exception!" + e.getMessage());
            return false;
        }
    }

    public boolean checkAndReturnCredentialManagerTimeoutFlag()  {

        Boolean checkCertsStatusOnTimeout=true;

        if(FileUtils.isExist(FILE_CERTS_PROPERTIES)) {
            checkCertsStatusOnTimeout = Boolean.parseBoolean(PropertiesReader.getPropertiesFromFileSystem(FILE_CERTS_PROPERTIES).
                    getProperty(CHECK_CERTS_STATUS_ONTIMEOUT, "true"));
            log.info("Properties file for checkCertsStatusOnTimeout value is  " +checkCertsStatusOnTimeout);
        }
        else
        {
            log.info("Properties file not found for checkCertsStatusOnTimeout");
        }

        return checkCertsStatusOnTimeout;
    }

}
