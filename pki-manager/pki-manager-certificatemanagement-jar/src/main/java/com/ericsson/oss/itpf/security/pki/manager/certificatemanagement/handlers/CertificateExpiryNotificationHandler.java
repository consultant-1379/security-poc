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

import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.CertExpiryNotificationsConstants;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.result.mapper.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.InternalAlarmGenerator;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.NotificationSeverity;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;

/**
 * Handles CA/Entity certificate expriry notifications and raises alarm if certificates expiry dates falls in between configured range.
 * 
 * @author tcsashc
 */
public class CertificateExpiryNotificationHandler {

    @Inject
    private Logger logger;

    @Inject
    EntitiesManager entitiesManager;

    @Inject
    InternalAlarmGenerator internalAlarmGenerator;

    @Inject
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Inject
    protected SystemRecorder systemRecorder;

    private final Map<String, Object> alarmDetails = new HashMap<>();

    /**
     * This method gets all certificates expire notification details based on entity type and raise the alarm if certificates expiry dates falls in between configured range.
     * 
     * @param entityType
     *            The entityType
     * 
     */
    public void handle(final EntityType entityType) {

        try {
            final Map<String, List<CertificateExpiryNotificationDetails>> certificateExpiryNotificationDetailsMap = getCertExpiryNotificationDetailsMap(entityType);

            if (certificateExpiryNotificationDetailsMap.isEmpty()) {
                logger.info("Certificate expiry datails are not found in the database or none of the certificate is going to expire");

            } else {

                for (final Map.Entry<String, List<CertificateExpiryNotificationDetails>> entry : certificateExpiryNotificationDetailsMap.entrySet()) {
                    final List<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetailsList = entry.getValue();
                    for (final CertificateExpiryNotificationDetails certificateExpiryNotificationDetails : certificateExpiryNotificationDetailsList) {
                        if (certificateExpiryNotificationDetails.getNumberOfDays() <= certificateExpiryNotificationDetails.getPeriodBeforeExpiry()) {

                            final boolean raiseAlaram = checkAlarmCanBeRaised(certificateExpiryNotificationDetails);
                            if (raiseAlaram) {
                                generateAlarm(certificateExpiryNotificationDetails, entityType);
                            }
                            break;
                        }
                    }
                }
            }
        } catch (PersistenceException persistenceException) {
            logger.error("Error occured while fetching certificate expiry notification details");
        }
    }

    private void generateAlarm(final CertificateExpiryNotificationDetails certificateExpiryNotificationDetails, final EntityType entityType) {
        final NotificationSeverity notificationSeverity = NotificationSeverity.getNotificationSeverity(certificateExpiryNotificationDetails
                .getNotificationSeverity());
        final String entityName = certificateExpiryNotificationDetails.getName();
        final String subjectDn = certificateExpiryNotificationDetails.getSubjectDN();
        final String serialNumber = certificateExpiryNotificationDetails.getSerialNumber();
        final int days = certificateExpiryNotificationDetails.getNumberOfDays();

        String problemTextMsg = null;
        if (entityType == EntityType.CA_ENTITY) {
            problemTextMsg = "Certificate for CA Entity: " + entityName + " with SubjectDN: " + subjectDn + " and Serial Number: " + serialNumber
                    + " expires in " + days + " DAYS";
        } else {
            problemTextMsg = "Certificate for End Entity: " + entityName + " with SubjectDN: " + subjectDn + " and Serial Number: " + serialNumber
                    + " expires in " + days + " DAYS";
        }

        alarmDetails.put(CertExpiryNotificationsConstants.NAME, entityName);
        alarmDetails.put(CertExpiryNotificationsConstants.EVENT_TYPE, "SecurityServiceOrMechanismViolation");
        alarmDetails.put(CertExpiryNotificationsConstants.PROBABLE_CAUSE, "KeyExpiry");
        alarmDetails.put(CertExpiryNotificationsConstants.SPECIFIC_PROBLEM, "CERTIFICATE EXPIRY");
        alarmDetails.put(CertExpiryNotificationsConstants.PERCEIVED_SEVERITY, notificationSeverity.toString());
        alarmDetails.put(CertExpiryNotificationsConstants.RECORD_TYPE, "ALARM");
        alarmDetails.put(CertExpiryNotificationsConstants.MANAGED_OBJECT_INSTANCE, "Entity=" + entityName);
        alarmDetails.put(CertExpiryNotificationsConstants.SERIAL_NUMBER, serialNumber);
        alarmDetails.put(CertExpiryNotificationsConstants.PROBLEM_TEXT, problemTextMsg);
        internalAlarmGenerator.raiseInternalAlarm(alarmDetails);
    }

    private boolean checkAlarmCanBeRaised(final CertificateExpiryNotificationDetails certificateExpiryNotificationDetails) {

        boolean raiseAlarm = false;
        final int periodBeforeExpiry = certificateExpiryNotificationDetails.getPeriodBeforeExpiry();
        final int numberOfDaysToExpire = certificateExpiryNotificationDetails.getNumberOfDays();
        final int frequencyOfNotification = certificateExpiryNotificationDetails.getFrequencyOfNotification();

        if ((periodBeforeExpiry - numberOfDaysToExpire) % frequencyOfNotification == 0) {
            raiseAlarm = true;
        }
        return raiseAlarm;
    }

    private Map<String, List<CertificateExpiryNotificationDetails>> getCertExpiryNotificationDetailsMap(final EntityType entityType) throws PersistenceException {

        final Map<String, List<CertificateExpiryNotificationDetails>> certificateExpiryNotificationDetailsMap = new HashMap<>();

        final List<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsLists = certificatePersistenceHelper.getCertExpiryNotificationDetails(entityType);

        for (final CertificateExpiryNotificationDetails certExpiryNotificationDetails : certExpiryNotificationDetailsLists) {

            final List<CertificateExpiryNotificationDetails> certExpiryNotificationDetailsList = new ArrayList<>();

            if (certificateExpiryNotificationDetailsMap.containsKey(certExpiryNotificationDetails.getSerialNumber())) {
                final List<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetailsDTOList = certificateExpiryNotificationDetailsMap.get(certExpiryNotificationDetails
                        .getSerialNumber());
                certificateExpiryNotificationDetailsDTOList.add(certExpiryNotificationDetails);
                certificateExpiryNotificationDetailsMap.put(certExpiryNotificationDetails.getSerialNumber(), certificateExpiryNotificationDetailsDTOList);
            } else {
                certExpiryNotificationDetailsList.add(certExpiryNotificationDetails);
                certificateExpiryNotificationDetailsMap.put(certExpiryNotificationDetails.getSerialNumber(), certExpiryNotificationDetailsList);
            }
        }

        return certificateExpiryNotificationDetailsMap;
    }

}
