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

import javax.xml.datatype.DatatypeFactory;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.NotificationSeverity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateExpiryNotificationDetailsData;

@RunWith(MockitoJUnitRunner.class)
public class CertificateExpiryNotificationDetailsMapperTest {

    @InjectMocks
    CertificateExpiryNotificationDetailsMapper certExpiryNotificationDetailsMapper;

    @Test
    public void testFromAPIToModel() throws Exception {
        Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.CRITICAL);
        certExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_PERIOD_BEFORE_EXPIRY_CRITICAL));
        certExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_FREQUENCY_OF_NOTIFICATION_CRITICAL));
        certificateExpiryNotificationDetailsSet.add(certExpiryNotificationDetails);
        Set<CertificateExpiryNotificationDetailsData> certExpiryNotificationDetailsData = certExpiryNotificationDetailsMapper.fromAPIToModel(certificateExpiryNotificationDetailsSet,
                Constants.CA_CERTIFICATE_EXPIRY_NOTIFICATION_MESSAGE);
        assertNotNull(certExpiryNotificationDetailsData);
    }

    @Test
    public void testoAPIfromModel() {

        Set<CertificateExpiryNotificationDetailsData> certificateExpiryNotificationDetailsDataSet = new HashSet<CertificateExpiryNotificationDetailsData>();
        CertificateExpiryNotificationDetailsData certExpiryNotificationDetailsData = new CertificateExpiryNotificationDetailsData();
        certExpiryNotificationDetailsData.setNotificationSeverity(4);
        certExpiryNotificationDetailsData.setPeriodBeforeExpiry(180);
        certExpiryNotificationDetailsData.setFrequencyOfNotification(7);
        certificateExpiryNotificationDetailsDataSet.add(certExpiryNotificationDetailsData);
        Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetails = certExpiryNotificationDetailsMapper.toAPIFromModel(certificateExpiryNotificationDetailsDataSet);
        assertNotNull(certExpiryNotificationDetails);

    }

}
