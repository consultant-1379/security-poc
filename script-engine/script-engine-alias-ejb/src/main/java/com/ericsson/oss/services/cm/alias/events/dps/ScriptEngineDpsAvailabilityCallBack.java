package com.ericsson.oss.services.cm.alias.events.dps;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.datalayer.dps.availability.DpsAvailabilityCallback;

/**
 * Checks database availability.
 */
@ApplicationScoped
public class ScriptEngineDpsAvailabilityCallBack implements DpsAvailabilityCallback {

    // Has to be static logger, DPS will not be able to inject Logger
    private final Logger logger = LoggerFactory.getLogger(ScriptEngineDpsAvailabilityCallBack.class);

    @Inject
    private DatabaseStatus databaseStatus;

    /**
     * {@inheritDoc}
     */
    @Override
    public void onServiceAvailable() {
        logger.warn("[Script-Engine availability] DPS is available again.");
        databaseStatus.setAvailable(true);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void onServiceUnavailable() {
        logger.warn("[Script-Engine Unavailability] DPS is unavailable.");
        databaseStatus.setAvailable(false);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getCallbackName() {
        return ScriptEngineDpsAvailabilityCallBack.class.getCanonicalName();
    }
}