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

import static org.junit.Assert.assertNotNull;

import java.util.Date;

import javax.xml.datatype.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class DateUtilTest {

    @InjectMocks
    private DateUtil dateUtil;

    private Duration duration;

    private static final String durationString = "PT1H1M30S";

    /**
     * Prepares initial data.
     * 
     * @throws DatatypeConfigurationException
     */
    @Before
    public void setUp() throws DatatypeConfigurationException {

        duration = DatatypeFactory.newInstance().newDuration(durationString);
    }

    /**
     * Method to test current time.
     */
    @Test
    public void testGetCurrentDate() {
        final Date currentDate = dateUtil.getCurrentDate();
        assertNotNull(currentDate);
    }

    /**
     * Method to test addition of date and duration.
     * 
     * @throws DatatypeConfigurationException
     *             {@link DatatypeConfigurationException}
     */
    @Test
    public void testSubtractDurationFromDate() throws DatatypeConfigurationException {
        final Date addDurationToDate = dateUtil.subtractDurationFromDate(new Date(), duration);
        assertNotNull(addDurationToDate);
    }

    /**
     * Method to test addition of date and duration.
     * 
     * @throws DatatypeConfigurationException
     *             {@link DatatypeConfigurationException}
     */
    @Test
    public void testAddDurationFromDate() throws DatatypeConfigurationException {
        final Date addDurationToDate = dateUtil.addDurationToDate(new Date(), duration);
        assertNotNull(addDurationToDate);
    }
}
