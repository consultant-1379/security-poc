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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.entity;

import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.Set;

import javax.xml.datatype.DatatypeFactory;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.NotificationSeverity;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entity.EntityCertificateExpiryNotificationDetailsValidator;

@RunWith(MockitoJUnitRunner.class)
public class EntityCertificateExpiryNotificationDetailsValidatorTest {

    @InjectMocks
    EntityCertificateExpiryNotificationDetailsValidator abstractEntityValidator;

    @Spy
    Logger logger = LoggerFactory.getLogger(EntityCertificateExpiryNotificationDetailsValidator.class);

    @Test
    public void testvalidateCertificateExpiryNotificationDetailsCriticalSuccess() throws Exception {

        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.CRITICAL);
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P1D"));
        certExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P30D"));
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);

        abstractEntityValidator.validateCertificateExpiryNotificationDetails(certExpiryNotificationDetailsSet);

    }

    @Test
    public void testvalidateCertificateExpiryNotificationDetailsCritical_InvalidPeriodBeforeExpiry() throws Exception {

        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.CRITICAL);
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P1D"));
        certExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P35D"));
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);
        try {
            abstractEntityValidator.validateCertificateExpiryNotificationDetails(certExpiryNotificationDetailsSet);
        } catch (InvalidEntityAttributeException invalidEntityAttributeException) {
            assertTrue(invalidEntityAttributeException.getMessage().contains("PeriodBeforeExpiry should be between 1 and 30 in case of CRITICAL Severity"));
        }
    }

    @Test
    public void testvalidateCertificateExpiryNotificationDetailsCritical_InvalidFrequencyOfNotification() throws Exception {

        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.CRITICAL);
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P7D"));
        certExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P30D"));
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);
        try {
            abstractEntityValidator.validateCertificateExpiryNotificationDetails(certExpiryNotificationDetailsSet);
        } catch (InvalidEntityAttributeException invalidEntityAttributeException) {
            assertTrue(invalidEntityAttributeException.getMessage().contains("Frequency of Notification should be 1 in case of CRITICAL Severity"));
        }
    }

    @Test
    public void testvalidateCertificateExpiryNotificationDetailsMajorSuccess() throws Exception {

        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.MAJOR);
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P2D"));
        certExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P60D"));
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);

        abstractEntityValidator.validateCertificateExpiryNotificationDetails(certExpiryNotificationDetailsSet);

    }

    @Test
    public void testvalidateCertificateExpiryNotificationDetailsMajor_InvalidPeriodBeforeExpiry() throws Exception {

        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.MAJOR);
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P2D"));
        certExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P65D"));
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);
        try {
            abstractEntityValidator.validateCertificateExpiryNotificationDetails(certExpiryNotificationDetailsSet);
        } catch (InvalidEntityAttributeException invalidEntityAttributeException) {
            assertTrue(invalidEntityAttributeException.getMessage().contains("PeriodBeforeExpiry should be between 31 and 60 in case of MAJOR Severity"));
        }
    }

    @Test
    public void testvalidateCertificateExpiryNotificationDetailsMajor_InvalidFrequencyOfNotification() throws Exception {

        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.MAJOR);
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P7D"));
        certExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P60D"));
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);
        try {
            abstractEntityValidator.validateCertificateExpiryNotificationDetails(certExpiryNotificationDetailsSet);
        } catch (InvalidEntityAttributeException invalidEntityAttributeException) {
            assertTrue(invalidEntityAttributeException.getMessage().contains("Frequency of Notification should be 1 or 2 in case of MAJOR Severity"));
        }
    }

    @Test
    public void testvalidateCertificateExpiryNotificationDetailsWarningSuccess() throws Exception {

        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.WARNING);
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P1D"));
        certExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P35D"));
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);
        try {
            abstractEntityValidator.validateCertificateExpiryNotificationDetails(certExpiryNotificationDetailsSet);
        } catch (InvalidEntityAttributeException invalidEntityAttributeException) {
            assertTrue(invalidEntityAttributeException.getMessage().contains(""));
        }
    }

    @Test
    public void testvalidateCertificateExpiryNotificationDetailsWarning_InvalidPeriodBeforeExpiry() throws Exception {

        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.WARNING);
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P4D"));
        certExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P95D"));
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);
        try {
            abstractEntityValidator.validateCertificateExpiryNotificationDetails(certExpiryNotificationDetailsSet);
        } catch (InvalidEntityAttributeException invalidEntityAttributeException) {
            assertTrue(invalidEntityAttributeException.getMessage().contains("PeriodBeforeExpiry should be between 61 and 90 in case of WARNING Severity"));
        }
    }

    @Test
    public void testvalidateCertificateExpiryNotificationDetailsWarning_InvalidFrequencyOfNotification() throws Exception {

        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.WARNING);
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P5D"));
        certExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P90D"));
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);
        try {
            abstractEntityValidator.validateCertificateExpiryNotificationDetails(certExpiryNotificationDetailsSet);
        } catch (InvalidEntityAttributeException invalidEntityAttributeException) {
            assertTrue(invalidEntityAttributeException.getMessage().contains("Frequency of Notification should be between 1 and 4 in case of WARNING Severity"));
        }
    }

    @Test
    public void testvalidateCertificateExpiryNotificationDetailsMinorSuccess() throws Exception {

        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.MINOR);
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P7D"));
        certExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P180D"));
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);
        try {
            abstractEntityValidator.validateCertificateExpiryNotificationDetails(certExpiryNotificationDetailsSet);
        } catch (InvalidEntityAttributeException invalidEntityAttributeException) {
            assertTrue(invalidEntityAttributeException.getMessage().contains(""));
        }
    }

    @Test
    public void testvalidateCertificateExpiryNotificationDetailsMinor_InvalidPeriodBeforeExpiry() throws Exception {

        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.MINOR);
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P7D"));
        certExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P185D"));
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);
        try {
            abstractEntityValidator.validateCertificateExpiryNotificationDetails(certExpiryNotificationDetailsSet);
        } catch (InvalidEntityAttributeException invalidEntityAttributeException) {
            assertTrue(invalidEntityAttributeException.getMessage().contains("PeriodBeforeExpiry should be betweeen 91 and 180 in case of MINOR Severity"));
        }
    }

    @Test
    public void testvalidateCertificateExpiryNotificationDetailsMinor_InvalidFrequencyOfNotification() throws Exception {

        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.MINOR);
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P8D"));
        certExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P180D"));
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);
        try {
            abstractEntityValidator.validateCertificateExpiryNotificationDetails(certExpiryNotificationDetailsSet);
        } catch (InvalidEntityAttributeException invalidEntityAttributeException) {
            assertTrue(invalidEntityAttributeException.getMessage().contains("Frequency of Notification should be between 1 and 7 in case of MINOR Severity"));
        }
    }

    @Test
    public void testvalidateCertificateExpiryNotificationDetails_NullPeriodBeforeExpiry() throws Exception {

        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.MINOR);
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P7D"));
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);
        try {
            abstractEntityValidator.validateCertificateExpiryNotificationDetails(certExpiryNotificationDetailsSet);
        } catch (InvalidEntityAttributeException invalidEntityAttributeException) {
            assertTrue(invalidEntityAttributeException.getMessage().contains("Mandatory field Period Before Expiry is Missing"));
        }
    }

    @Test
    public void testvalidateCertificateExpiryNotificationDetails_NullFrequencyOfNotification() throws Exception {

        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.MINOR);
        certExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P180D"));
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);

        try {
            abstractEntityValidator.validateCertificateExpiryNotificationDetails(certExpiryNotificationDetailsSet);
        } catch (InvalidEntityAttributeException invalidEntityAttributeException) {
            assertTrue(invalidEntityAttributeException.getMessage().contains("Mandatory field Frequency of Notification is Missing"));
        }
    }

    @Test
    public void testvalidateCertificateExpiryNotificationDetails_NullNotificationSeverity() throws Exception {

        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P8D"));
        certExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P180D"));
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);

        try {
            abstractEntityValidator.validateCertificateExpiryNotificationDetails(certExpiryNotificationDetailsSet);
        } catch (InvalidEntityAttributeException invalidEntityAttributeException) {
            assertTrue(invalidEntityAttributeException.getMessage().contains("Mandatory field Notification Severity is Missing"));
        }
    }

    @Test
    public void testvalidateCertificateExpiryNotificationDetails_DuplicateNotificationSeverity() throws Exception {

        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.MINOR);
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P8D"));
        certExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P180D"));
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P7D"));

        CertificateExpiryNotificationDetails certExpiryNotificationDetails1 = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails1.setNotificationSeverity(NotificationSeverity.MINOR);
        certExpiryNotificationDetails1.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P8D"));
        certExpiryNotificationDetails1.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P175D"));
        certExpiryNotificationDetails1.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P7D"));
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);
        certExpiryNotificationDetailsSet.add(certExpiryNotificationDetails1);

        try {
            abstractEntityValidator.validateCertificateExpiryNotificationDetails(certExpiryNotificationDetailsSet);
        } catch (InvalidEntityAttributeException invalidEntityAttributeException) {
            assertTrue(invalidEntityAttributeException.getMessage().contains("Duplicate Notification Severity"));
        }
    }
}
