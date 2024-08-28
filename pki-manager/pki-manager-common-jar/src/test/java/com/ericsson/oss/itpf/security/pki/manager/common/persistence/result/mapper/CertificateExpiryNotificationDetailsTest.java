package com.ericsson.oss.itpf.security.pki.manager.common.persistence.result.mapper;

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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.result.mapper.CertificateExpiryNotificationDetails;

@RunWith(MockitoJUnitRunner.class)
public class CertificateExpiryNotificationDetailsTest {

    CertificateExpiryNotificationDetails actualCertificateExpiryNotificationDetailsDTO;
    CertificateExpiryNotificationDetails expectedcertificateExpiryNotificationDetailsDTO;

    @Before
    public void setUP() {
        actualCertificateExpiryNotificationDetailsDTO = getCertificateExpiryNotificationDetailsDTO();
        expectedcertificateExpiryNotificationDetailsDTO = getCertificateExpiryNotificationDetailsDTO();
    }

    @Test
    public void testEquals() {

        assertEquals(expectedcertificateExpiryNotificationDetailsDTO, actualCertificateExpiryNotificationDetailsDTO);

    }

    @Test
    public void testNotEquals() {

        actualCertificateExpiryNotificationDetailsDTO.setName(null);
        assertNotEquals(expectedcertificateExpiryNotificationDetailsDTO, actualCertificateExpiryNotificationDetailsDTO);

    }

    @Test
    public void testNotEqualsGetName() {
        actualCertificateExpiryNotificationDetailsDTO.setName("test");
        String name = actualCertificateExpiryNotificationDetailsDTO.getName();
        assertEquals(name, "test");

    }

    @Test
    public void testNotEqualsGetSubjectDN() {
        actualCertificateExpiryNotificationDetailsDTO.setSubjectDN("test");
        String name = actualCertificateExpiryNotificationDetailsDTO.getSubjectDN();
        assertEquals(name, "test");

    }

    @Test
    public void testNotEqualsGetSerialnumber() {
        actualCertificateExpiryNotificationDetailsDTO.setSerialNumber("test");
        String name = actualCertificateExpiryNotificationDetailsDTO.getSerialNumber();
        assertEquals(name, "test");

    }

    @Test
    public void testNotEqualsGetNumberOfdays() {
        actualCertificateExpiryNotificationDetailsDTO.setNumberOfDays(4);
        int name = actualCertificateExpiryNotificationDetailsDTO.getNumberOfDays();
        assertEquals(name, 4);

    }

    @Test
    public void testNotEqualsGetPeriodBeforeExpiry() {
        actualCertificateExpiryNotificationDetailsDTO.setPeriodBeforeExpiry(4);
        int name = actualCertificateExpiryNotificationDetailsDTO.getPeriodBeforeExpiry();
        assertEquals(name, 4);

    }

    @Test
    public void testNotEqualsGetNotificationSeverity() {
        actualCertificateExpiryNotificationDetailsDTO.setNotificationSeverity(4);
        int name = actualCertificateExpiryNotificationDetailsDTO.getNotificationSeverity();
        assertEquals(name, 4);

    }

    @Test
    public void testNotEqualsGetFrequencyOfNotification() {
        actualCertificateExpiryNotificationDetailsDTO.setFrequencyOfNotification(4);
        int name = actualCertificateExpiryNotificationDetailsDTO.getFrequencyOfNotification();
        assertEquals(name, 4);

    }


    @Test
    public void testNotEqualsGetNotificationMessage() {
        actualCertificateExpiryNotificationDetailsDTO.setNotificationMessage("test");
        String name = actualCertificateExpiryNotificationDetailsDTO.getNotificationMessage();
        assertEquals(name, "test");

    }


    private CertificateExpiryNotificationDetails getCertificateExpiryNotificationDetailsDTO() {

        final CertificateExpiryNotificationDetails certificateExpiryNotificationDetailsDTO1 = new CertificateExpiryNotificationDetails();
        certificateExpiryNotificationDetailsDTO1.setName("CAEntity");
        certificateExpiryNotificationDetailsDTO1
                .setNotificationMessage("Certificate for CA Entity: {caName} With SubjectDN {subjectDN} and Serial Number {serialNumber} will expire in {numberOfDays} DAYS.Refer Security System Administration Guide for  Certificate Reissue procedure.");
        certificateExpiryNotificationDetailsDTO1.setNotificationSeverity(1);
        certificateExpiryNotificationDetailsDTO1.setFrequencyOfNotification(1);
        certificateExpiryNotificationDetailsDTO1.setNumberOfDays(27);
        certificateExpiryNotificationDetailsDTO1.setSerialNumber("12341223435");
        certificateExpiryNotificationDetailsDTO1.setSubjectDN("CN=ARJ_Root");
        certificateExpiryNotificationDetailsDTO1.setPeriodBeforeExpiry(30);

        return certificateExpiryNotificationDetailsDTO1;
    }

}
