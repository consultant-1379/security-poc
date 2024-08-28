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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps;

import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.TDPSPublishStatusType;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.builders.TDPSCertificateEventBuilder;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.builders.TDPSCertificateInfoBuilder;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.mappers.*;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.sender.TDPSCertificateEventSender;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSCertificateEvent;

/**
 * This class is a Notifer class which notifies pki-ra-tdps with a TDPSCertificateEvent.
 * 
 * @author tcsdemi
 *
 */
public class TDPSEventNotificationService {

    @Inject
    TDPSCertificateEventSender tdpsCertificateEventSender;

    @Inject
    TDPSCertificateStatusTypeMapper tDPSCertificateStatusTypeMapper;

    @Inject
    TDPSOperationTypeMapper tdpsOperationTypeMapper;

    @Inject
    TDPSEntityTypeMapper tdpsEntityTypeMapper;

    /**
     * This method fires TDPSNotification to pki-ra-tdps
     * 
     * @param tdpsNotification
     * @throws CertificateEncodingException
     */
    public void fireCertificateEvent(final EntityType entityType, final String entityName, final TDPSPublishStatusType tDPSPublishStatusType, final List<Certificate> certificates)
            throws CertificateEncodingException {
        if (!isCertificateEventNotificationValid(entityType, entityName, tDPSPublishStatusType, certificates)) {
            return;
        }

        CertificateEventInfo certificateEventInfo = null;
        TDPSCertificateEvent tDPSCertificateEvent = null;
        final int certificateSize = certificates.size();
        // below logic is used to fire only 100 or below 100 TDPSNotifications at a time to pki-ra-tdps
        if (certificateSize < 100) {
            certificateEventInfo = generateCertificateEventInfo(entityType, entityName, tDPSPublishStatusType, certificates);
            tDPSCertificateEvent = buildTDPSCertificateEvent(certificateEventInfo);
            tdpsCertificateEventSender.send(tDPSCertificateEvent);
        } else {
            final int offset = 100;
            int min = 0;
            int max = 100;
            while (max <= certificateSize && min <= max) {
                final List<Certificate> certs = certificates.subList(min, max);
                certificateEventInfo = generateCertificateEventInfo(entityType, entityName, tDPSPublishStatusType, certs);
                tDPSCertificateEvent = buildTDPSCertificateEvent(certificateEventInfo);
                tdpsCertificateEventSender.send(tDPSCertificateEvent);
                min = max + 1;

                if (certificateSize > max + offset) {
                    max = max + offset;
                } else {
                    max = certificateSize;
                }
            }
        }

    }

    private boolean isCertificateEventNotificationValid(final EntityType entityType, final String entityName, final TDPSPublishStatusType tDPSPublishStatusType, final List<Certificate> certificates) {
        if (entityType == null) {
            return false;
        }

        if (entityName == null) {
            return false;
        }

        if (tDPSPublishStatusType == null) {
            return false;
        }

        if (certificates == null) {
            return false;
        }

        return true;
    }

    private CertificateEventInfo generateCertificateEventInfo(final EntityType entityType, final String entityName, final TDPSPublishStatusType tDPSPublishStatusType,
            final List<Certificate> certificates) {
        final CertificateEventInfo certificateEventInfo = new CertificateEventInfo();

        certificateEventInfo.setEntityName(entityName);
        certificateEventInfo.setEntityType(entityType);
        certificateEventInfo.setCertificates(certificates);
        certificateEventInfo.setPublishType(tDPSPublishStatusType);

        return certificateEventInfo;
    }

    private TDPSCertificateEvent buildTDPSCertificateEvent(final CertificateEventInfo certificateEventInfo) throws CertificateEncodingException {
        final List<TDPSCertificateInfo> tdpsCertificateInfos = buildTDPSCertificateInfos(certificateEventInfo);
        final TDPSCertificateEventBuilder tDPSCertificateEventBuilder = new TDPSCertificateEventBuilder().publishType(tdpsOperationTypeMapper.toModel(certificateEventInfo.getPublishType()))
                .tDPSCertificateInfo(tdpsCertificateInfos);

        return tDPSCertificateEventBuilder.build();
    }

    private List<TDPSCertificateInfo> buildTDPSCertificateInfos(final CertificateEventInfo certificateEventInfo) throws CertificateEncodingException {
        final List<Certificate> certificates = certificateEventInfo.getCertificates();
        final List<TDPSCertificateInfo> certificateInfos = new ArrayList<TDPSCertificateInfo>();

        for (final Certificate certificate : certificates) {
            final TDPSCertificateInfoBuilder tdpsCertificateInfoBuilder = new TDPSCertificateInfoBuilder().certificate(certificate.getX509Certificate().getEncoded())
                    .entityName(certificateEventInfo.getEntityName()).entityType(tdpsEntityTypeMapper.toModel(certificateEventInfo.getEntityType())).serialNumber(certificate.getSerialNumber())
                    .tDPSCertificateStatusType(tDPSCertificateStatusTypeMapper.toModel(certificate.getStatus())).issuerName(certificate.getIssuer().getName());
            certificateInfos.add(tdpsCertificateInfoBuilder.build());
        }

        return certificateInfos;
    }
}