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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper;

import static org.junit.Assert.assertNotNull;

import java.util.HashSet;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.common.helpers.DefaultCertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;

@RunWith(MockitoJUnitRunner.class)
public class DefaultCertificateExpiryNotificationDetailsTest {

    @InjectMocks
    DefaultCertificateExpiryNotificationDetails defaultCertExpiryNotificationDetails;

    @Test
    public void testPrepareDefaultCertificateExpiryNotificationDetails() {
        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetails = new HashSet<CertificateExpiryNotificationDetails>();
        certExpiryNotificationDetails = defaultCertExpiryNotificationDetails.prepareDefaultCertificateExpiryNotificationDetails();
        assertNotNull(certExpiryNotificationDetails);
        for (CertificateExpiryNotificationDetails certExpiryNotificationDetail : certExpiryNotificationDetails) {
            assertNotNull(certExpiryNotificationDetail.getNotificationSeverity());
            assertNotNull(certExpiryNotificationDetail.getFrequencyOfNotification());
            assertNotNull(certExpiryNotificationDetail.getPeriodBeforeExpiry());
        }

    }

}
