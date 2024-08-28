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
package com.ericsson.oss.itpf.security.pki.manager.common.validator;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import javax.persistence.PersistenceException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.validator.OtpValidator;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityInfoData;

@RunWith(MockitoJUnitRunner.class)
public class OtpValidatorTest {

    @InjectMocks
    OtpValidator otpValidator;

    @Mock
    private PersistenceManager persistenceManager;

    @Mock
    Logger logger;

    @Test
    public void testIsOtpValid() {
        final String entityName = "entityName";
        final String otp = "otp";

        final EntityData entityData = new EntityData();
        final EntityInfoData entityInfoData = new EntityInfoData();
        entityInfoData.setOtpCount(1);
        entityInfoData.setOtp(otp);
        entityData.setEntityInfoData(entityInfoData);
        when(persistenceManager.findEntityByName(EntityData.class, entityName, "entityInfoData.name")).thenReturn(entityData);

        when(persistenceManager.updateEntity(entityData)).thenReturn(entityData);

        assertTrue(otpValidator.isOtpValid(entityName, otp));
    }

    @Test
    public void testIsOtpValidHavingWrongOtp() {
        final String entityName = "entityName";
        final String otp = "otp";

        final EntityData entityData = new EntityData();
        final EntityInfoData entityInfoData = new EntityInfoData();
        entityInfoData.setOtpCount(1);
        entityInfoData.setOtp("some otp");
        entityData.setEntityInfoData(entityInfoData);
        when(persistenceManager.findEntityByName(EntityData.class, entityName, "entityInfoData.name")).thenReturn(entityData);

        when(persistenceManager.updateEntity(entityData)).thenReturn(entityData);

        assertFalse(otpValidator.isOtpValid(entityName, otp));
    }

    @Test
    public void testIsOtpValidHavingEntityDataAsNull() {
        final String entityName = "entityName";
        final String otp = "otp";
        boolean isEntityNotFoundExceptionCaught = false;
        String errorMessage = "";

        when(persistenceManager.findEntityByName(EntityData.class, entityName, "entityInfoData.name")).thenReturn(null);

        try {
            otpValidator.isOtpValid(entityName, otp);
        } catch (final EntityNotFoundException entityNotFoundException) {
            isEntityNotFoundExceptionCaught = true;
            errorMessage = entityNotFoundException.getMessage();
        }

        assertTrue(isEntityNotFoundExceptionCaught);
        assertEquals("Entity Not found Exception", errorMessage);
    }

    @Test
    public void testIsOtpValidHavingOtpCountAsZero() {
        final String entityName = "entityName";
        final String otp = "otp";
        boolean isOTPExpiredExceptionCaught = false;
        String errorMessage = "";

        final EntityData entityData = new EntityData();
        final EntityInfoData entityInfoData = new EntityInfoData();
        entityInfoData.setOtpCount(0);
        entityInfoData.setOtp(otp);
        entityData.setEntityInfoData(entityInfoData);
        when(persistenceManager.findEntityByName(EntityData.class, entityName, "entityInfoData.name")).thenReturn(entityData);

        try {
            otpValidator.isOtpValid(entityName, otp);
        } catch (final OTPExpiredException otpExpiredException) {
            isOTPExpiredExceptionCaught = true;
            errorMessage = otpExpiredException.getMessage();
        }

        assertTrue(isOTPExpiredExceptionCaught);
        assertEquals("OTP Expired", errorMessage);
    }

    @Test
    public void testIsOtpValidThrowsPersistenceException() {
        final String entityName = "entityName";
        final String otp = "otp";
        boolean isEntityServiceExceptionCaught = false;
        String errorMessage = "";

        doThrow(PersistenceException.class).when(persistenceManager).findEntityByName(EntityData.class, entityName, "entityInfoData.name");

        try {
            otpValidator.isOtpValid(entityName, otp);
        } catch (final EntityServiceException entityServiceException) {
            isEntityServiceExceptionCaught = true;
            errorMessage = entityServiceException.getMessage();
        }

        assertTrue(isEntityServiceExceptionCaught);
        assertEquals("Failed to extract entity ", errorMessage);
    }
}
