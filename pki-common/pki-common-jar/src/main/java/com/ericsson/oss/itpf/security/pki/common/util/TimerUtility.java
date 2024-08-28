/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.common.util;

import javax.ejb.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.util.exception.TimerException;

/**
 * This class will provide the utility methods - create and cancel an EJB timer service.
 * 
 * @author tcsnapa
 *
 */
public class TimerUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(StringUtility.class);

    private TimerUtility() {

    }

    /**
     * This method will create and return an EJB timer with the given timer interval and the timer config parameter.
     * 
     * @param timerService
     *            is the EJB timer service.
     * @param timerInterval
     *            the interval time to create an EJB timer.
     * @param timerInfo
     *            a serializable object which defines the TimerConfig uniquely.
     * @throws TimerException
     *             is thrown when failed to create an EJB timer.
     */
    public static void createTimer(final TimerService timerService, final String timerInterval, final String timerInfo) throws TimerException {
        LOGGER.info("Configuring timer service with timer Interval [{}] and timer info [{}]", timerInterval, timerInfo);
        final ScheduleExpression schedule = StringUtility.getScheduleExpressionFromString(timerInterval);
        final TimerConfig timerConfig = new TimerConfig(timerInfo, false);
        try {
            timerService.createCalendarTimer(schedule, timerConfig);
        } catch (IllegalArgumentException | IllegalStateException | EJBException e) {
            LOGGER.error("Unable to create the timer with the timer config {}", timerInfo);
            throw new TimerException("Unable to create the timer with the timer config " + timerInfo, e);
        }
    }

    /**
     * This method will cancels the existing timer for the given TimerService and with the given timer configuration.
     * 
     * @param timerService
     *            EJB TimerService.
     * @param timerInfo
     *            a serializable object which defines the TimerConfig uniquely.
     * @throws TimerException
     *             is thrown when failed to cancel an EJB timer.
     */
    public static void cancelTimerByTimerConfig(final TimerService timerService, final String timerInfo) throws TimerException {
        if (timerService.getTimers() != null) {
            for (Timer timer : timerService.getTimers()) {
                if (timer.getInfo().equals(timerInfo)) {
                    try {
                        timer.cancel();
                    } catch (IllegalStateException | EJBException e) {
                        LOGGER.error("Unable to cancel the timer for the timer config {}", timerInfo);
                        throw new TimerException("Unable to cancel the timer with the timer config " + timerInfo, e);
                    }
                }
            }
        }
    }
}
