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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.processor;

import java.util.List;


import javax.ejb.EJB;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.edt.*;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseAckMessage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers.CACertificateInfoEventMapper;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CRLManagementLocalService;

/**
 * CRLResponseAckMessageProcessor class will update the update CRL Status in DB
 * 
 * @author xjagcho
 * 
 */
public class CRLResponseAckMessageProcessor {

    @Inject
    private CACertificateInfoEventMapper caCertificateInfoEventMapper;

    @EJB
    public CRLManagementLocalService crlManagementLocalService;

    @Inject
    private Logger logger;

    /**
     * This process method process the CRL Response Acknowledgement Message data
     * 
     * @param crlResponseAckMessage
     *            it holds list of CACertificateInfo and Operation type and response type
     */
    public void process(final CRLResponseAckMessage crlResponseAckMessage) {
        handleMessage(crlResponseAckMessage);
    }

    private void handleMessage(final CRLResponseAckMessage crlResponseAckMessage) {

        final List<CACertificateInfo> caCertificateInfo = crlResponseAckMessage.getCaCertificateInfoList();
        if (caCertificateInfo != null && !(caCertificateInfo.isEmpty())) {
            final List<CACertificateIdentifier> caCertificateIdentifiers = caCertificateInfoEventMapper.toModel(caCertificateInfo);

            if (crlResponseAckMessage.getCdpsResponseType().equals(CDPSResponseType.SUCCESS)) {
                updateCRLStatus(caCertificateIdentifiers, crlResponseAckMessage.getCdpsOperationType(), crlResponseAckMessage.getUnpublishReasonType());
            } else {
                logger.error("Unknown/Failure Response type during {} CRLs for {} ", crlResponseAckMessage.getCdpsOperationType(), crlResponseAckMessage.getCaCertificateInfoList());
            }
        } else {
            logger.error("Received Null/Empty CA certificate info list");
        }
    }

    private void updateCRLStatus(final List<CACertificateIdentifier> caCertificateIdentifiers, final CDPSOperationType cdpsOperationType, final UnpublishReasonType unpublishReasonType) {
        switch (cdpsOperationType) {
        case PUBLISH:
            crlManagementLocalService.updateCRLPublishUnpublishStatus(caCertificateIdentifiers, true);
            break;

        case UNPUBLISH:
            updateUnpublishedCRLs(caCertificateIdentifiers, unpublishReasonType);
            break;

        default:
            break;
        }
    }

    private void updateUnpublishedCRLs(final List<CACertificateIdentifier> caCertificateIdentifiers, final UnpublishReasonType unpublishReasonType) {
        if (!(ValidationUtils.isNullOrEmpty(caCertificateIdentifiers))) {
            if (UnpublishReasonType.REVOKED_CA_CERTIFICATE.equals(unpublishReasonType) || UnpublishReasonType.EXPIRED_CA_CERTIFICATE.equals(unpublishReasonType)) {
                crlManagementLocalService.deleteInvalidCRLs(caCertificateIdentifiers);
            } else {
                crlManagementLocalService.updateCRLPublishUnpublishStatus(caCertificateIdentifiers, false);
            }
        }
    }
}
