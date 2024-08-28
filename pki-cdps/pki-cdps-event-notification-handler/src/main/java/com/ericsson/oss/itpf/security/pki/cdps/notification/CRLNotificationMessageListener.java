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
package com.ericsson.oss.itpf.security.pki.cdps.notification;

import java.util.List;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.annotation.Modeled;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.edt.CDPSOperationType;
import com.ericsson.oss.itpf.security.pki.cdps.edt.CDPSResponseType;
import com.ericsson.oss.itpf.security.pki.cdps.event.*;
import com.ericsson.oss.itpf.security.pki.cdps.notification.builders.CRLRequestMessageBuilder;
import com.ericsson.oss.itpf.security.pki.cdps.notification.builders.CRLResponseAckMessageBuilder;
import com.ericsson.oss.itpf.security.pki.cdps.notification.events.UnpublishCRLEvent;
import com.ericsson.oss.itpf.security.pki.cdps.notification.instrumentation.CRLInstrumentationBean;

/**
 * CRLNotificationMessageListener will listen the CRLNotificationMessage from the ClusteredCRLNotificationChannel. Once the event is received the event will be sent to the CRLRequestProcessor.
 * 
 * @author xjagcho
 */
@ApplicationScoped
public class CRLNotificationMessageListener {

    @Inject
    CRLAcknowledgementSender crlAcknowledgementSender;

    @Inject
    CRLRequestMessageSender crlRequestMessageSender;

    @Inject
    private Logger logger;

    @Inject
    private UnpublishCRLEvent unPublishCRLEvent;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    CRLInstrumentationBean crlInstrumentationBean;

    /**
     * This method listen the CRLNotificationMessage and process it to prepare CRLRequestMessage and send it to PKI Manager over a channel
     * 
     * @param crlNotificationMessage
     *            crlNotificationMessage holds list of CACertificateInfo it contains caName,SerialNumber,CdpsOperationType and UnpublishReasonType
     */
    public void listenForCRLNotificationMessageEvents(@Observes @Modeled final CRLNotificationMessage crlNotificationMessage) {
        try {
            handleMessage(crlNotificationMessage);
        } catch (Exception exception) {
            logger.error("Exception caught while processing the CRLRequestMessage in CRLNotificationMessageListener " + exception.getMessage());
            logger.debug("Caught exception while listening the CRLNotificationMessage in CRLNotificationMessageListener {}  ", exception.getMessage(), exception);
            throw exception;
        }
    }

    /**
     * This handleMessage method handles crlNotificationMessage with operation type
     * 
     * @param crlNotificationMessage
     *            crlNotificationMessage holds list of CACertificateInfo it contains caName,SerialNumber,CdpsOperationType and UnpublishReasonType
     */
    private void handleMessage(final CRLNotificationMessage crlNotificationMessage) {
        logger.debug("Begin of handleMessage of CRLNotificationMessageListener class");

        switch (crlNotificationMessage.getCdpsOperationType()) {
        case PUBLISH:
            crlInstrumentationBean.setPublishMethodInvocations();
            sendCRLRequestMessage(crlNotificationMessage.getCaCertificateInfoList()); // send the event to pki-manager to get CRLs to be published.
            break;

        case UNPUBLISH:
            unPublishCRLEvent.execute(crlNotificationMessage.getCaCertificateInfoList(), crlNotificationMessage.getUnpublishReasonType());
            break;

        default:
            logger.error("Invalid CDPS Operation type from the CRLNotificationMessage");
            systemRecorder.recordError("PKI_CDPS.INVALID_CDPS_OPEARTION", ErrorSeverity.ERROR, "PKI CA", "CDPSService", "Invalid CDPS Operation type is received from CA");

            sendCRLAckMessage(crlNotificationMessage.getCaCertificateInfoList(), crlNotificationMessage.getCdpsOperationType(), CDPSResponseType.FAILURE);
        }

        logger.debug("End of handleMessage of CRLNotificationMessageEvent");
    }

    /**
     * This method sends the CRL Request message to the pki-manager along with list of CACertificateInfo
     * 
     * @param caCertificateInfoList
     *            it holds the list of CACertificateInfo and it contains caName and SerialNumber
     */
    private void sendCRLRequestMessage(final List<CACertificateInfo> caCertificateInfoList) {
        final CRLRequestMessage crlRequestMessage = (new CRLRequestMessageBuilder()).caCertificateInfos(caCertificateInfoList).build();
        crlRequestMessageSender.sendMessage(crlRequestMessage);
    }

    /**
     * This sendCRLAckMessage method sends the Acknowledgement to the pki-manager
     * 
     * @param caCertificateInfoList
     *            it holds the list of CACertificateInfo and it contains caName and SerialNumber
     * @param cdpsOperationType
     *            it is the type of the Publish or UnPublish
     * @param cdpsResponseType
     *            it is the type of the success or failure
     */
    private void sendCRLAckMessage(final List<CACertificateInfo> caCertificateInfoList, final CDPSOperationType cdpsOperationType, final CDPSResponseType cdpsResponseType) {
        final CRLResponseAckMessage crlResponseAckMessage = (new CRLResponseAckMessageBuilder()).caCertificateInfos(caCertificateInfoList).cdpsOperationType(cdpsOperationType)
                .cdpsResponseType(cdpsResponseType).build();
        crlAcknowledgementSender.sendMessage(crlResponseAckMessage);
    }
}