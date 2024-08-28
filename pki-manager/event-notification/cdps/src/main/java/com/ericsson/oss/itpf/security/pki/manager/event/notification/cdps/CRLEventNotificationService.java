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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps;

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.edt.CDPSOperationType;
import com.ericsson.oss.itpf.security.pki.cdps.edt.UnpublishReasonType;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLNotificationMessage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CRLUnpublishType;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.builders.CRLNotificationMessageBuilder;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers.CACertificateInfoEventMapper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers.UnpublishReasonTypeMapper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.sender.CRLNotificationMessageSender;

/**
 * This class handles the CRL Event Notification like CRL Publish and UnPublish
 * 
 * @author xjagcho
 *
 */
public class CRLEventNotificationService {
    @Inject
    private CACertificateInfoEventMapper caCertificateInfoEventMapper;

    @Inject
    private CRLNotificationMessageSender crlNotificationMessageSender;

    @Inject
    private UnpublishReasonTypeMapper unpublishReasonTypeMapper;

    @Inject
    private Logger logger;

    /**
     * This Method fires the Publish CRL related operations
     * 
     * @param caCertificateIdentifiers
     *            it holds the list of CACertificateIdentifier and it contains CAName and Certificate Serial Number
     */
    public void firePublishEvent(final List<CACertificateIdentifier> caCertificateIdentifiers) {
        if (!caCertificateIdentifiers.isEmpty()) {
            final List<CACertificateInfo> caCertificateInfos = caCertificateInfoEventMapper.fromModel(caCertificateIdentifiers);

            final CRLNotificationMessage crlNotificationMessage = (new CRLNotificationMessageBuilder()).caCertificateInfos(caCertificateInfos).cdpsOperationType(CDPSOperationType.PUBLISH).build();
            crlNotificationMessageSender.sendMessage(crlNotificationMessage);
        } else {
            logger.info("No CRL's for publish to CDPS");
        }

    }

    /**
     * This Method handles the UnPublish CRL related operations
     * 
     * @param caCertificateIdentifiers
     *            it contains the CACertificateIdentifier it holds CAName and Certificate Serial Number
     * 
     */
    public void fireUnpublishEvent(final List<CACertificateIdentifier> caCertificateIdentifiers) {
        logger.info("fireUnpublishEvent method in CRLEventNotificationService");
        if (!caCertificateIdentifiers.isEmpty()) {
            final List<CACertificateInfo> caCertificateInfos = caCertificateInfoEventMapper.fromModel(caCertificateIdentifiers);

            final CRLNotificationMessage crlNotificationMessage = (new CRLNotificationMessageBuilder()).caCertificateInfos(caCertificateInfos).cdpsOperationType(CDPSOperationType.UNPUBLISH).build();
            crlNotificationMessageSender.sendMessage(crlNotificationMessage);
        } else {
            logger.info("No CRL's for unpublish to CDPS");
        }
        logger.info("End of fireUnpublishEvent method in CRLEventNotificationService");
    }

    /**
     * This Method handles the UnPublish CRL related operations
     * 
     * @param caCertificateIdentifiers
     *            it contains the CACertificateIdentifier it holds CAName and Certificate Serial Number
     * 
     * @param unpublishType
     *            it holds the revoked_expired_ca_certificate ,crl_not_required_in_cdps
     */
    public void fireUnpublishEvent(final List<CACertificateIdentifier> caCertificateIdentifiers, final CRLUnpublishType crlUnpublishType) {
        logger.info("fireUnpublishEvent method in CRLEventNotificationService");
        final UnpublishReasonType unpublishReasonType = unpublishReasonTypeMapper.fromModel(crlUnpublishType);

        if (unpublishReasonType == null) {
            logger.debug("Unsupported CRL Publish Type, use this method only for revoked and expired ca certificates");
            return;
        }

        if (!caCertificateIdentifiers.isEmpty()) {
            final List<CACertificateInfo> caCertificateInfos = caCertificateInfoEventMapper.fromModel(caCertificateIdentifiers);

            final CRLNotificationMessage crlNotificationMessage = (new CRLNotificationMessageBuilder()).caCertificateInfos(caCertificateInfos).cdpsOperationType(CDPSOperationType.UNPUBLISH)
                    .unpublishReasonType(unpublishReasonType).build();
            crlNotificationMessageSender.sendMessage(crlNotificationMessage);
        } else {
            logger.info("No CRL's for unpublish to CDPS");
        }
        logger.info("End of fireUnpublishEvent method in CRLEventNotificationService");
    }
}
