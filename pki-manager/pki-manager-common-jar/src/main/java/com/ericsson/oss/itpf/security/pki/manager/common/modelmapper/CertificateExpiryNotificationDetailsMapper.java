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

import java.util.HashSet;
import java.util.Set;

import javax.xml.datatype.*;

import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.NotificationSeverity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateExpiryNotificationDetailsData;

/**
 * Converts CertificateExpiryNotificationDetails API model to CertificateExpiryNotificationDetailsData JPA model and vice versa.
 * 
 * @author tcsviku
 * 
 */
public class CertificateExpiryNotificationDetailsMapper {

    /**
     * Maps the CertificateExpiryNotificationDetails API model to its corresponding JPA model for CA Entity
     * 
     * @param certificateExpiryNotificationDetailsSet
     *            Set<CertificateExpiryNotificationDetails> which should be converted to JPA model Set<CertificateExpiryNotificationDetailsData>
     * 
     * @return the JPA model {@link Set<CertificateExpiryNotificationDetailsData>} of the given API model
     * 
     */
    public Set<CertificateExpiryNotificationDetailsData> fromAPIToModel(final Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetailsSet, final String notificationMessage) {

        final Set<CertificateExpiryNotificationDetailsData> certificateExpiryNotificationDetailsDataSet = new HashSet<CertificateExpiryNotificationDetailsData>();
        for (CertificateExpiryNotificationDetails certificateExpiryNotificationDetails : certificateExpiryNotificationDetailsSet) {
            CertificateExpiryNotificationDetailsData certificateExpiryNotificationDetailsData = null;
            certificateExpiryNotificationDetailsData = new CertificateExpiryNotificationDetailsData();
            certificateExpiryNotificationDetailsData.setNotificationSeverity(certificateExpiryNotificationDetails.getNotificationSeverity().getId());
            certificateExpiryNotificationDetailsData.setPeriodBeforeExpiry(certificateExpiryNotificationDetails.getPeriodBeforeExpiry().getDays());
            certificateExpiryNotificationDetailsData.setFrequencyOfNotification(certificateExpiryNotificationDetails.getFrequencyOfNotification().getDays());
            certificateExpiryNotificationDetailsData.setNotificationMessage(notificationMessage);
            certificateExpiryNotificationDetailsDataSet.add(certificateExpiryNotificationDetailsData);
        }

        return certificateExpiryNotificationDetailsDataSet;
    }

    /**
     * Maps the CertificateExpiryNotificationDetails JPA model to its corresponding API model
     * 
     * @param certificateExpiryNotificationDetailsDataSet
     *            Set<CertificateExpiryNotificationDetailsData> which should be converted to API model Set<CertificateExpiryNotificationDetail>
     * 
     * @return the API model {@link Set<CertificateExpiryNotificationDetails>} of the given JPA model
     * 
     */
    public Set<CertificateExpiryNotificationDetails> toAPIFromModel(final Set<CertificateExpiryNotificationDetailsData> certificateExpiryNotificationDetailsDataSet) {
        CertificateExpiryNotificationDetails certificateExpiryNotificationDetails = null;
        final Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
        for (CertificateExpiryNotificationDetailsData certificateExpiryNotificationDetailsData : certificateExpiryNotificationDetailsDataSet) {
            certificateExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
            final String periodBeforeExpiry1 = certificateExpiryNotificationDetailsData.getPeriodBeforeExpiry().toString();
            final String frequencyOfNotification1 = certificateExpiryNotificationDetailsData.getFrequencyOfNotification().toString();
            Duration periodBeforeExpiry = null;
            Duration frequencyOfNotification = null;
            try {
                periodBeforeExpiry = DatatypeFactory.newInstance().newDuration("P" + periodBeforeExpiry1 + "D");
                frequencyOfNotification = DatatypeFactory.newInstance().newDuration("P" + frequencyOfNotification1 + "D");
            } catch (DatatypeConfigurationException e) {
            }
            certificateExpiryNotificationDetails.setPeriodBeforeExpiry(periodBeforeExpiry);
            certificateExpiryNotificationDetails.setFrequencyOfNotification(frequencyOfNotification);
            certificateExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.getNotificationSeverity(certificateExpiryNotificationDetailsData.getNotificationSeverity()));
            certificateExpiryNotificationDetailsSet.add(certificateExpiryNotificationDetails);
        }

        return certificateExpiryNotificationDetailsSet;
    }

}
