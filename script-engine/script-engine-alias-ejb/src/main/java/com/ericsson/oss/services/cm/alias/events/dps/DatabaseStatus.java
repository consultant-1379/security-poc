package com.ericsson.oss.services.cm.alias.events.dps;

import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;
import javax.ejb.Lock;
import javax.ejb.LockType;
import javax.ejb.Singleton;
import javax.inject.Inject;

import org.slf4j.Logger;

/**
 * Holds the database status and logs the amount of time the database was unavailable for.
 */
@Singleton
public class DatabaseStatus {

    private boolean available = false;

    private Long startOfUnavailability = null;

    @Inject
    private Logger logger;

    @PostConstruct
    public void settingInitilaStatus() {
        if (System.getProperty("hack.for.integration.test.to.work.databasestatus.available") != null) {
            setAvailable(true);
        }
    }

    @Lock(LockType.READ)
    public boolean isAvailable() {
        return available;
    }

    @Lock(LockType.WRITE)
    public void setAvailable(final boolean available) {
        if (databaseHasBecomeUnavailable(available)) {
            startOfUnavailability = System.currentTimeMillis();
        }

        if (databaseHasBecomeAvailableAgain(available)) {
            final long databaseUnavailabilityTime = System.currentTimeMillis() - startOfUnavailability;
            startOfUnavailability = null;
            logger.warn("[Script-Engine Unavailability] Database was unavailable for {}.{} seconds.",
                    TimeUnit.MILLISECONDS.toSeconds(databaseUnavailabilityTime), databaseUnavailabilityTime % 1000);
        }

        this.available = available;
    }

    private boolean databaseHasBecomeAvailableAgain(final boolean available) {
        return available && startOfUnavailability != null;
    }

    private boolean databaseHasBecomeUnavailable(final boolean available) {
        return !available && startOfUnavailability == null;
    }
}