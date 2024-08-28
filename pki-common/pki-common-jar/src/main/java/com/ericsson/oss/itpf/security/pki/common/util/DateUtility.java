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
package com.ericsson.oss.itpf.security.pki.common.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.xml.datatype.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidDurationFormatException;

/**
 * This class deals with Date Operations.
 * 
 * @author tcsramc
 *
 */
public class DateUtility {

    private DateUtility() {

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(DateUtility.class);
    final SimpleDateFormat dateFormat = new SimpleDateFormat(Constants.SIMPLE_DATE_FORMAT);

    /**
     * This method is used to return Current UTC Date .
     * 
     * @return current UTC Date.
     */
    public static Date getUTCTime() {
        new DateUtility().dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        final SimpleDateFormat dateFormatLocal = new SimpleDateFormat(Constants.SIMPLE_DATE_FORMAT);
        try {
            return dateFormatLocal.parse(new DateUtility().dateFormat.format(new Date()));
        } catch (ParseException parseException) {
            LOGGER.error("Date can not parsed to UTC hence returning local time");
            LOGGER.debug("Exception stacktrace ", parseException);
            return new Date();
        }
    }

    /**
     * This method is used to get the current date in string format. *
     * 
     * @return date in string format.
     */
    public static String getDateinStringFormat(final Date date) {
        final SimpleDateFormat simpleDateFormat = new SimpleDateFormat(Constants.SIMPLE_DATE_FORMAT);
        simpleDateFormat.setTimeZone(Calendar.getInstance().getTimeZone());
        final String currentDate = simpleDateFormat.format(date);
        return currentDate;
    }

    /**
     * This method is used to convert current date from String(date in UTC Format) to date(as System date) format.
     * 
     * @param dateStringInUTCFormat
     *            String which in UTCformat and has to be converted to SystemDate format.
     * @return returns current date in System Date format.
     * @throws ParseException
     *             is thrown if any error occurs while parsing String to date format.
     */
    public static Date convertUTCtoSystemDate(final String dateStringInUTCFormat) throws ParseException {
        Date dateinLocalFormat = null;

        final SimpleDateFormat simpleDateFormat = new SimpleDateFormat(Constants.SIMPLE_DATE_FORMAT);
        final Date dateinUTC = simpleDateFormat.parse(dateStringInUTCFormat);

        final long currentTimeinMillis = System.currentTimeMillis();
        final Date localTime = new Date(currentTimeinMillis);
        dateinLocalFormat = new Date(dateinUTC.getTime() + TimeZone.getDefault().getOffset(localTime.getTime()));

        return dateinLocalFormat;
    }

    /**
     * This method is used to convert current date from String to date format.
     * 
     * @param dateToConvert
     * 
     * @return returns current date in Date format.
     */
    public static Date toDate(final String dateToConvert) {
        Date date = null;
        try {
            date = new DateUtility().dateFormat.parse(dateToConvert);

        } catch (ParseException parseException) {
            LOGGER.error("Date can not parsed to UTC hence returning local time");
            LOGGER.debug("Exception stacktrace ", parseException);
            return new Date();
        }
        return date;
    }

    /**
     * Method returns current date
     * 
     * @return current Date
     */
    public static Date getCurrentDate() {

        final Calendar validFrom = Calendar.getInstance();
        final Date notBefore = validFrom.getTime();

        return notBefore;
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
    public static Date subtractDurationFromDate(final Date date, final Duration duration) {

        final Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(Calendar.YEAR, -duration.getYears());
        cal.add(Calendar.MONTH, -duration.getMonths());
        cal.add(Calendar.DAY_OF_MONTH, -duration.getDays());
        cal.add(Calendar.HOUR, -duration.getHours());
        cal.add(Calendar.MINUTE, -duration.getMinutes());
        cal.add(Calendar.SECOND, -duration.getSeconds());

        final Date dateAfterDuration = cal.getTime();
        return dateAfterDuration;
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
    public static Date addDurationToDate(final Date date, final Duration duration) {

        final Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(Calendar.YEAR, duration.getYears());
        cal.add(Calendar.MONTH, duration.getMonths());
        cal.add(Calendar.DAY_OF_MONTH, duration.getDays());
        cal.add(Calendar.HOUR, duration.getHours());
        cal.add(Calendar.MINUTE, duration.getMinutes());
        cal.add(Calendar.SECOND, duration.getSeconds());

        final Date dateAfterDuration = cal.getTime();
        return dateAfterDuration;
    }

    /**
     * This method converts the String time representation to XML data type Duration
     * 
     * @param timeAsString
     *            is the String representation of the time parameters.
     * @return XML data type duration notation of the String input
     * @throws InvalidDurationFormatException
     *             is thrown when failed to convert String to Duration.
     */
    public static Duration convertStringToDuration(final String timeAsString) throws InvalidDurationFormatException {
        if (timeAsString != null) {
            DatatypeFactory d = null;
            try {
                d = DatatypeFactory.newInstance();
                final Duration timeAsDuration = d.newDuration(timeAsString);
                return timeAsDuration;
            } catch (DatatypeConfigurationException | IllegalArgumentException e) {
                LOGGER.error(ErrorMessages.FAILED_TO_CONVERT_STRING_TO_DURATION);
                throw new InvalidDurationFormatException(ErrorMessages.FAILED_TO_CONVERT_STRING_TO_DURATION, e);
            }
        }
        return null;
    }
}
