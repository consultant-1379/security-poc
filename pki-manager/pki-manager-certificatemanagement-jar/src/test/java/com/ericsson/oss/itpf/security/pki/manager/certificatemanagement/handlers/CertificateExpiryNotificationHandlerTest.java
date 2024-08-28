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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.result.mapper.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.InternalAlarmGenerator;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

@RunWith(MockitoJUnitRunner.class)
public class CertificateExpiryNotificationHandlerTest {

    @InjectMocks
    CertificateExpiryNotificationHandler certificateExpiryNotificationHandler;

    @Mock
    Logger logger;

    @Mock
    static PersistenceManager persistenceManager;

    @Mock
    EntityManager entityManager;

    @Mock
    InternalAlarmGenerator internalAlarmGenerator;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    Query query;

    List<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetailsList;

    /**
     * Prepares initial set up required to run the test cases.
     */

    @Before
    public void setUp() {
        certificateExpiryNotificationDetailsList = new ArrayList<CertificateExpiryNotificationDetails>();

        final CertificateExpiryNotificationDetails certificateExpiryNotificationDetailsDTO1 = new CertificateExpiryNotificationDetails();
        certificateExpiryNotificationDetailsDTO1.setName("CAENTITY");
        certificateExpiryNotificationDetailsDTO1.setSubjectDN("CN=ARJ_ROOTCA");
        certificateExpiryNotificationDetailsDTO1.setSerialNumber("4af7cb2ef4ea");
        certificateExpiryNotificationDetailsDTO1.setNumberOfDays(25);
        certificateExpiryNotificationDetailsDTO1.setPeriodBeforeExpiry(30);
        certificateExpiryNotificationDetailsDTO1.setNotificationSeverity(1);
        certificateExpiryNotificationDetailsDTO1.setFrequencyOfNotification(1);
        certificateExpiryNotificationDetailsDTO1
                .setNotificationMessage("Certificate for CA Entity: CAEntity With SubjectDN CN=ARJ_ROOT_CA and Serial Number 4af7cb2ef4ea will expire in 25 DAYS.Refer Security System Administration Guide for  Certificate Reissue procedure.");

        final CertificateExpiryNotificationDetails certificateExpiryNotificationDetailsDTO2 = new CertificateExpiryNotificationDetails();
        certificateExpiryNotificationDetailsDTO2.setName("CAENTITY");
        certificateExpiryNotificationDetailsDTO2.setSubjectDN("CN=ARJ_ROOTCA");
        certificateExpiryNotificationDetailsDTO2.setSerialNumber("4af7cb2ef4ea");
        certificateExpiryNotificationDetailsDTO2.setNumberOfDays(55);
        certificateExpiryNotificationDetailsDTO2.setPeriodBeforeExpiry(60);
        certificateExpiryNotificationDetailsDTO2.setNotificationSeverity(1);
        certificateExpiryNotificationDetailsDTO2.setFrequencyOfNotification(1);
        certificateExpiryNotificationDetailsDTO2
                .setNotificationMessage("Certificate for CA Entity: CAEntity With SubjectDN CN=ARJ_ROOT_CA and Serial Number 4af7cb2ef4ea will expire in 25 DAYS.Refer Security System Administration Guide for  Certificate Reissue procedure.");

        certificateExpiryNotificationDetailsList.add(certificateExpiryNotificationDetailsDTO1);
        certificateExpiryNotificationDetailsList.add(certificateExpiryNotificationDetailsDTO2);
    }

    /**
     * Test case for get ca certificate expire notification details
     */
    @Test
    public void testHandleCACertNotificationDetails() {
        Mockito.when(certificatePersistenceHelper.getCertExpiryNotificationDetails(EntityType.CA_ENTITY)).thenReturn(certificateExpiryNotificationDetailsList);
        Mockito.doNothing().when(internalAlarmGenerator).raiseInternalAlarm(Mockito.anyMap());
        certificateExpiryNotificationHandler.handle(EntityType.CA_ENTITY);
        Mockito.verify(certificatePersistenceHelper).getCertExpiryNotificationDetails(EntityType.CA_ENTITY);
        Mockito.verify(internalAlarmGenerator).raiseInternalAlarm(Mockito.anyMap());
    }

    /**
     * Method to test for CA empty handler
     */
    @Test
    public void testHandleCACertNotificationDetails_Empty() {
        final List<CertificateExpiryNotificationDetails> certExpiryNotificationDetails = new ArrayList<CertificateExpiryNotificationDetails>();
        Mockito.when(certificatePersistenceHelper.getCertExpiryNotificationDetails(EntityType.CA_ENTITY)).thenReturn(certExpiryNotificationDetails);
        certificateExpiryNotificationHandler.handle(EntityType.CA_ENTITY);
        Mockito.verify(certificatePersistenceHelper).getCertExpiryNotificationDetails(EntityType.CA_ENTITY);
    }

    /**
     * Method to test for ca Persistence Exception
     */
    @Test
    public void testHandleCACertNotificationDetails_PersistenceException() throws Exception {
        Mockito.when(certificatePersistenceHelper.getCertExpiryNotificationDetails(EntityType.CA_ENTITY)).thenThrow(
                new PersistenceException("Error occured while fetching certificate expiry notification details"));
        certificateExpiryNotificationHandler.handle(EntityType.CA_ENTITY);
    }

    /**
     * Method to test for entity handler
     */
    @Test
    public void testHandleEntityCertNotificationDetails() {
        Mockito.when(certificatePersistenceHelper.getCertExpiryNotificationDetails(EntityType.ENTITY)).thenReturn(certificateExpiryNotificationDetailsList);
        Mockito.doNothing().when(internalAlarmGenerator).raiseInternalAlarm(Mockito.anyMap());
        certificateExpiryNotificationHandler.handle(EntityType.ENTITY);
        Mockito.verify(certificatePersistenceHelper).getCertExpiryNotificationDetails(EntityType.ENTITY);
        Mockito.verify(internalAlarmGenerator).raiseInternalAlarm(Mockito.anyMap());

    }

    /**
     * Method to test for entity empty handler
     */
    @Test
    public void testHandleEntityCertNotificationDetails_empty() {
        final List<CertificateExpiryNotificationDetails> certExpiryNotificationDetails = new ArrayList<CertificateExpiryNotificationDetails>();
        Mockito.when(certificatePersistenceHelper.getCertExpiryNotificationDetails(EntityType.ENTITY)).thenReturn(certExpiryNotificationDetails);
        certificateExpiryNotificationHandler.handle(EntityType.ENTITY);
        Mockito.verify(certificatePersistenceHelper).getCertExpiryNotificationDetails(EntityType.ENTITY);
    }

    /**
     * Method to test for entity Persistence Exception
     */
    @Test
    public void testHandleEntityCertNotificationDetails_PersistenceException() throws Exception {
        Mockito.when(certificatePersistenceHelper.getCertExpiryNotificationDetails(EntityType.ENTITY)).thenThrow(
                new PersistenceException("Error occured while fetching certificate expiry notification details"));
        certificateExpiryNotificationHandler.handle(EntityType.CA_ENTITY);
    }

}
