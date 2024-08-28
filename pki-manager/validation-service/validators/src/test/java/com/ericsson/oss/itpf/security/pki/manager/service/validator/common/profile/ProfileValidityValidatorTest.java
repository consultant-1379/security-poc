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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile;

import java.util.Calendar;
import java.util.Date;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;

@RunWith(MockitoJUnitRunner.class)
public class ProfileValidityValidatorTest {

    @Mock
    Logger logger;

    @InjectMocks
    ProfileValidityValidator profileValidityValidator;

    public static final int ONE_DAY = 1000 * 60 * 60 * 24;
    
    /**
     * This method tests validate method in positive scenario
     */
    @Test
    public void testValidDate() {
        Date currentDate = new Date();
        Date tomorrow = new Date(currentDate.getTime() + ONE_DAY);
        
        profileValidityValidator.validate(tomorrow);
    }

    /**
     * This method tests validate method in negative scenario
     */
    @Test(expected = InvalidProfileAttributeException.class)
    public void testInValidDate() {
        final Calendar cal = Calendar.getInstance();
        cal.setTime(new Date());
        cal.add(Calendar.DATE, -30);
        final Date dateBefore30Days = cal.getTime();
        profileValidityValidator.validate(dateBefore30Days);
        Mockito.verify(logger).error("Profile has expired already!");

    }
}
