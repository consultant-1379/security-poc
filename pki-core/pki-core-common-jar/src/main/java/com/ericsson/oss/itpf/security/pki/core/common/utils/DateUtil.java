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
package com.ericsson.oss.itpf.security.pki.core.common.utils;

import java.util.Calendar;
import java.util.Date;

import javax.xml.datatype.Duration;

/**
 * Utility class for all Date related operations
 * 
 */
public class DateUtil {

    /**
     * Method returns current date
     * 
     * @return current Date
     */
    public Date getCurrentDate() {

        final Calendar validFrom = Calendar.getInstance();
        return validFrom.getTime();
    }

    /**
     * Method subtracts duration to date and returns the new Date value
     * 
     * @param date
     *            initial date
     * @param duration
     *            duration to be added to date
     * @return final date after adding duration
     */
    public Date subtractDurationFromDate(final Date date, final Duration duration) {

        final Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(Calendar.YEAR, -duration.getYears());
        cal.add(Calendar.MONTH, -duration.getMonths());
        cal.add(Calendar.DAY_OF_MONTH, -duration.getDays());
        cal.add(Calendar.HOUR, -duration.getHours());
        cal.add(Calendar.MINUTE, -duration.getMinutes());
        cal.add(Calendar.SECOND, -duration.getSeconds());
        return cal.getTime();
    }

    /**
     * Method adds duration to date and returns the new Date value
     * 
     * @param date
     *            initial date
     * @param duration
     *            duration to be added to date
     * @return final date after adding duration
     */
    public Date addDurationToDate(final Date date, final Duration duration) {

        final Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(Calendar.YEAR, duration.getYears());
        cal.add(Calendar.MONTH, duration.getMonths());
        cal.add(Calendar.DAY_OF_MONTH, duration.getDays());
        cal.add(Calendar.HOUR, duration.getHours());
        cal.add(Calendar.MINUTE, duration.getMinutes());
        cal.add(Calendar.SECOND, duration.getSeconds());
        return  cal.getTime();
    }

}
