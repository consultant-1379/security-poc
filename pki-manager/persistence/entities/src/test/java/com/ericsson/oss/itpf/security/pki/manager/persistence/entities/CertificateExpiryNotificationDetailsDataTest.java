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
package com.ericsson.oss.itpf.security.pki.manager.persistence.entities;

import static org.junit.Assert.*;

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.model.NotificationSeverity;

@RunWith(MockitoJUnitRunner.class)
public class CertificateExpiryNotificationDetailsDataTest {

    @InjectMocks
    CertificateExpiryNotificationDetailsData certExpiryNotificationDetailsData;

    protected CertificateExpiryNotificationDetailsData createInstance() throws Exception {
        return createCertificateExpiryNotificationDetailsData();
    }

    protected CertificateExpiryNotificationDetailsData createNotEqualInstance() throws Exception {
        return createCertificateExpiryNotificationDetailsDataNotEqual();
    }

    @Test
    public void testWithEachFieldNull() throws Exception {
        final CertificateExpiryNotificationDetailsData certExpiryNotificationDetailsData = createInstance();
        final Class<? extends Object> certExpiryNotificationDetailsDataClass = certExpiryNotificationDetailsData.getClass();
        final Object nullObject = null;
        final Method[] methods = certExpiryNotificationDetailsDataClass.getMethods();
        Object tempObject1 = null;
        Object tempObject2 = null;
        for (final Method method : methods) {
            if (method.getName().startsWith("set")) {
                if (method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum() && !method.getParameterTypes()[0].isInterface()) {

                    tempObject1 = createNotEqualInstance();
                    tempObject2 = createNotEqualInstance();

                    method.invoke(tempObject2, nullObject);
                    method.invoke(tempObject1, nullObject);

                    assertNotEquals(certExpiryNotificationDetailsData, tempObject1);
                    assertNotEquals(tempObject1, certExpiryNotificationDetailsData);
                    assertEquals(tempObject1, tempObject2);
                }
            }
        }
    }

    @Test
    public void testMethod() throws CertificateEncodingException, CertificateException, IOException {
        assertNotNull(certExpiryNotificationDetailsData.toString());
        assertNotNull(certExpiryNotificationDetailsData.hashCode());
    }

    private CertificateExpiryNotificationDetailsData createCertificateExpiryNotificationDetailsData() throws CertificateEncodingException, CertificateException, IOException {
        final CertificateExpiryNotificationDetailsData certExpiryNotificationDetailsData = new CertificateExpiryNotificationDetailsData();
        certExpiryNotificationDetailsData.setId(5);
        certExpiryNotificationDetailsData.setNotificationSeverity(NotificationSeverity.MINOR.getId());
        certExpiryNotificationDetailsData.setPeriodBeforeExpiry(180);
        certExpiryNotificationDetailsData.setFrequencyOfNotification(7);
        certExpiryNotificationDetailsData
                .setNotificationMessage("Certificate for CA Entity: {caName} With SubjectDN {subjectDN} and Serial Number {serialNumber} will expire in {numberOfDays} DAYS.Refer Security System Administration Guide for  Certificate Reissue procedure.");

        return certExpiryNotificationDetailsData;

    }

    private CertificateExpiryNotificationDetailsData createCertificateExpiryNotificationDetailsDataNotEqual() throws CertificateEncodingException, CertificateException, IOException {
        final CertificateExpiryNotificationDetailsData certExpiryNotificationDetailsData = new CertificateExpiryNotificationDetailsData();
        certExpiryNotificationDetailsData.setId(certExpiryNotificationDetailsData.getId());
        certExpiryNotificationDetailsData.setNotificationSeverity(certExpiryNotificationDetailsData.getNotificationSeverity());
        certExpiryNotificationDetailsData.setPeriodBeforeExpiry(certExpiryNotificationDetailsData.getPeriodBeforeExpiry());
        certExpiryNotificationDetailsData.setFrequencyOfNotification(certExpiryNotificationDetailsData.getFrequencyOfNotification());
        certExpiryNotificationDetailsData.setNotificationMessage(certExpiryNotificationDetailsData.getNotificationMessage());

        return certExpiryNotificationDetailsData;

    }

}
