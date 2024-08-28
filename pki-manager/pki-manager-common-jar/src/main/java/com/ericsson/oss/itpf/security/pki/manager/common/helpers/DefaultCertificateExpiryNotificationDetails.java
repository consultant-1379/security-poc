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
package com.ericsson.oss.itpf.security.pki.manager.common.helpers;

import java.util.HashSet;
import java.util.Set;

import javax.xml.datatype.*;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.NotificationSeverity;

/**
 * This Class is for preparing CertificateExpiryNotificationDetails.
 * 
 * @author tcsviku
 * 
 */
public class DefaultCertificateExpiryNotificationDetails {

    /**
     * This method prepare default values of Certificate Expiry Notification Details.
     * 
     * @return default @link Set<CertificateExpiryNotificationDetails>
     */
    public Set<CertificateExpiryNotificationDetails> prepareDefaultCertificateExpiryNotificationDetails() {

        final Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetails = new HashSet<CertificateExpiryNotificationDetails>();

        try {
            certificateExpiryNotificationDetails.add(getCertificateExpiryNotificationDetails(NotificationSeverity.CRITICAL,
                    DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_PERIOD_BEFORE_EXPIRY_CRITICAL),
                    DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_FREQUENCY_OF_NOTIFICATION_CRITICAL)));
            certificateExpiryNotificationDetails.add(getCertificateExpiryNotificationDetails(NotificationSeverity.MAJOR,
                    DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_PERIOD_BEFORE_EXPIRY_MAJOR),
                    DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_FREQUENCY_OF_NOTIFICATION_MAJOR)));
            certificateExpiryNotificationDetails.add(getCertificateExpiryNotificationDetails(NotificationSeverity.WARNING,
                    DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_PERIOD_BEFORE_EXPIRY_WARNING),
                    DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_FREQUENCY_OF_NOTIFICATION_WARNING)));
            certificateExpiryNotificationDetails.add(getCertificateExpiryNotificationDetails(NotificationSeverity.MINOR,
                    DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_PERIOD_BEFORE_EXPIRY_MINOR),
                    DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_FREQUENCY_OF_NOTIFICATION_MINOR)));
            return certificateExpiryNotificationDetails;
        } catch (final DatatypeConfigurationException e) {
        }

        return certificateExpiryNotificationDetails;
    }

    public CertificateExpiryNotificationDetails getCertificateExpiryNotificationDetails(final NotificationSeverity notificationSeverity, final Duration periodBeforeExpiry,
            final Duration frequencyOfNotification) {

        final CertificateExpiryNotificationDetails certificateExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
        certificateExpiryNotificationDetails.setNotificationSeverity(notificationSeverity);
        certificateExpiryNotificationDetails.setPeriodBeforeExpiry(periodBeforeExpiry);
        certificateExpiryNotificationDetails.setFrequencyOfNotification(frequencyOfNotification);
        return certificateExpiryNotificationDetails;

    }

}
