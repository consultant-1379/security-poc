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

package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.handler;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.IPResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPResponse;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ResponseSignerException;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.SynchResponseHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.qualifiers.ProtocolResponseType;
import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.CMPLocalService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.MessageSignerService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.CertificateEnrollmentStatusUtility;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;

/**
 * This class handles initialization response sent from PKI-Manager, implements <code> ResponseHandler</code>. Message is extracted from modeled event
 * and saved into DB with status as
 * "wait for acknowledgement".
 * 
 * @author tcsdemi
 */
@ProtocolResponseType(Constants.TYPE_INIT_RESPONSE)
public class InitializationResponseHandler implements ResponseHandler {

    @EServiceRef
    CMPLocalService cmpLocalService;

    @EServiceRef
    MessageSignerService messageSignerService;

    @Inject
    SynchResponseHandler handler;

    @Inject
    CertificateEnrollmentStatusUtility certificateEnrollmentStatusUtility;

    @Inject
    PersistenceHandler persistenceHandler;

    @Inject
    Logger logger;

    @Override
    public byte[] handle(final CMPResponse cMPResponse) throws ResponseSignerException, PersistenceException {

        final String transactionID = cMPResponse.getTransactionID();
        final byte[] ipResponseFromManager = cMPResponse.getCmpResponse();
        final String senderName = cMPResponse.getEntityName();
        final String errorInfo = cMPResponse.getErrorInfo();

        logger.info("Received IP response with transaction id [{}] and entity name [{}]", transactionID, senderName);
        if (cMPResponse.getSyncResponse()) {
            logger.info("Received SYNC IP response with transaction id [{}] and entity name [{}]", transactionID, senderName);
            handleSyncResponse(cMPResponse);
        } else {
            cmpLocalService.updateCMPTransactionStatus(transactionID, senderName, ipResponseFromManager, MessageStatus.WAIT_FOR_ACK, errorInfo);
        }

        return ipResponseFromManager;
    }

    private void handleSyncResponse(final CMPResponse cMPResponse) throws ResponseSignerException {
        try {
            final String transactionID = cMPResponse.getTransactionID();
            final String senderName = cMPResponse.getEntityName();
            final IPResponseMessage ipResponseMessage = createIPResponseMessage(cMPResponse);
            final String senderNonce = ipResponseMessage.getSenderNonce();
            final String errorInfo = cMPResponse.getErrorInfo();
            final CMPMessageEntity cMPMessageEntity = persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
            final byte[] signedResponseMessage = messageSignerService.signMessage(cMPResponse.getIssuerName(), ipResponseMessage);

            cmpLocalService.updateCMPTransactionStatus(transactionID, senderName, signedResponseMessage, senderNonce, errorInfo);
            handler.handleResponseAndSendNotification(transactionID, signedResponseMessage);
            final String subjectName = certificateEnrollmentStatusUtility.extractSubjectNameFromInitialMessage(cMPMessageEntity.getInitialMessage());
            certificateEnrollmentStatusUtility.buildAndDispatchCertificateEnrollmentStatus(subjectName, cMPResponse.getIssuerName(), errorInfo);

        } catch (final IOException ioException) {
            throw new ResponseSignerException(ErrorMessages.IO_EXCEPTION, ioException);

        } catch (final CertificateException certificateException) {
            throw new ResponseSignerException(ErrorMessages.CERTIFICATE_EXCEPTION, certificateException);
        }
    }

    private IPResponseMessage createIPResponseMessage(final CMPResponse cMPResponse) throws CertificateException, IOException {

        final String sender = messageSignerService.getSenderFromSignerCert(cMPResponse.getIssuerName());
        final String recipientName = cMPResponse.getEntityName();
        final String transactionID = cMPResponse.getTransactionID();
        final byte[] protectionAlgorithm = cMPResponse.getProtectionAlgorithm();
        final byte[] responseFromManager = cMPResponse.getCmpResponse();

        final IPResponseMessage ipResponseMessage = new IPResponseMessage(responseFromManager);
        final List<X509Certificate> cMPextraCertificates =
                messageSignerService.buildCMPExtraCertsForResponseFromManager(cMPResponse.getIssuerName(), ipResponseMessage);
        final String senderNonce = ipResponseMessage.getSenderNonce();
        final String recipientNonce = ipResponseMessage.getReceipientNonce();

        ipResponseMessage.setProtectionAlgorithm(protectionAlgorithm);
        ipResponseMessage.createPKIHeader(sender, recipientName, senderNonce, recipientNonce, transactionID);
        ipResponseMessage.createPKIMessage(cMPextraCertificates);

        return ipResponseMessage;
    }

}
