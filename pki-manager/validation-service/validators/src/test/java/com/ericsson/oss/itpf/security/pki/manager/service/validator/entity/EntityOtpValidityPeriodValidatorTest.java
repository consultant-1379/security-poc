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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entity;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.InvalidOtpValidityPeriodException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;

@RunWith(MockitoJUnitRunner.class)
public class EntityOtpValidityPeriodValidatorTest {

    @InjectMocks
    EntityOtpValidityPeriodValidator entityOtpValidityPeriodValidator;

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityOtpValidityPeriodValidator.class);
    private final static int MIN_VALUE = 1;

    private final static int MAX_VALUE = 1440;

    /**
     * This method is to test Positive scenario for OTPValidityPeriod
     */
    @Test
    public void testOtpValidityPeriod() {
        Entity entity = new Entity();
        entity.setOtpValidityPeriod(1);
        entityOtpValidityPeriodValidator.validate(entity);
    }

    /**
     * This method is to test negative scenario for OTPValidityPeriod
     */
    @Test(expected = InvalidOtpValidityPeriodException.class)
    public void testInvalidOtpValidityPeriod() {
        Entity entity = new Entity();
        entity.setOtpValidityPeriod(1441);
        entityOtpValidityPeriodValidator.validate(entity);
        Mockito.verify(logger).debug("OTP Validity Period value is not with in the " + MIN_VALUE + " & " + MAX_VALUE);
    }

    /**
     * This method is to test Positive scenario for existing entities with OTPValidityPeriod value as -1
     */
    @Test
    public void testOtpValidityPeriod_ForExistingEntity() {
        Entity entity = new Entity();
        entity.setOtpValidityPeriod(-1);
        entityOtpValidityPeriodValidator.validate(entity);
    }

}
