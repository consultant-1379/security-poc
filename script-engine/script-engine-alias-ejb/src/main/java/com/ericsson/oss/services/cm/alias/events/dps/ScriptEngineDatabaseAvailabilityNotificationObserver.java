package com.ericsson.oss.services.cm.alias.events.dps;


import javax.annotation.PostConstruct;
import javax.ejb.Lock;
import javax.ejb.LockType;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerConfig;
import javax.ejb.TimerService;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.datalayer.dps.DataPersistenceService;
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;

/**
 * Observes database availability callbacks
 */
@Singleton
@Startup
public class ScriptEngineDatabaseAvailabilityNotificationObserver {

    @EServiceRef
    private DataPersistenceService dps;

    @Inject
    private ScriptEngineDpsAvailabilityCallBack callback;

    @Inject
    private TimerService timerService;

    @Inject
    private Logger logger;

    private static final int MAX_ATTEMPTS = 20;
    private static final int STARTUP_TIMER = 60000;         // 60 sec.
    private static final int ATTEMPT_INTERVAL = 10000;       // 10 sec.

    private static int error_count = 0;

    /**
     * Schedule a job to be executed via the {@code TimerService}
     */
    @PostConstruct
    public void scheduleListenerForDpsNotification() {
        error_count = 0;
        setAttemptsTimer(STARTUP_TIMER);
    }

    /**
     * Callback method to be called on expiry of timeout registered in {#scheduleListenerForDpsNotification} method.
     */
    @Timeout
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Lock(LockType.READ)
    public void listenForDpsNotifications(final Timer timer) {

        error_count++;
        if (error_count > MAX_ATTEMPTS) {
            logger.error("DPS failed to deploy within at least {} seconds", MAX_ATTEMPTS * ATTEMPT_INTERVAL / 1000);
        } else {
            try {
                dps.registerDpsAvailabilityCallback(callback);
                final String message = String
                    .format("Registering DPS availability callback for ScriptEngine. Attempt %d of %d", error_count, MAX_ATTEMPTS);
                if (error_count == 1) {
                    logger.info(message);
                } else {
                    logger.warn(message);
                }
            } catch (Exception e) {
                logger.warn("An unexpected {} occurred during DPS availability callback registration: {}", e.getClass().getCanonicalName(),
                       e.getMessage());
                setAttemptsTimer(ATTEMPT_INTERVAL);
            }
        }
    }

    private void setAttemptsTimer(final long duration) {
        final TimerConfig timerConfig = new TimerConfig();
        timerConfig.setPersistent(false);
        timerService.createSingleActionTimer(duration, timerConfig);
    }
}