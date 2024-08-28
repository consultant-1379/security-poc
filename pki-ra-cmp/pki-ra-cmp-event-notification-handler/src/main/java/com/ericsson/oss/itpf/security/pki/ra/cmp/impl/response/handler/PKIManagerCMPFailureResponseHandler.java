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

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.FailureResponseMessage;
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
 * This class handles error response sent from PKI-Manager, implements <code> ResponseHandler</code>. Message is extracted from modeled event and
 * saved into DB with status as "Error".
 * 
 * @author tcsdemi
 */
@ProtocolResponseType(Constants.TYPE_ERROR_RESPONSE)
public class PKIManagerCMPFailureResponseHandler implements ResponseHandler {

    @Inject
    Logger logger;

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

    @Override
    public byte[] handle(final CMPResponse cMPResponse) throws ResponseSignerException {

        final String transactionID = cMPResponse.getTransactionID();
        final String senderName = cMPResponse.getEntityName();
        final String errorInfo = cMPResponse.getErrorInfo();

        logger.debug("Received ERROR response with transaction id [{}] and error [{}]", transactionID, errorInfo);
        final byte[] responseFromManager = cMPResponse.getCmpResponse();

        if (cMPResponse.getSyncResponse()) {
            logger.debug("Received SYNC ERROR response with transaction id [{}]", transactionID);
            handleSyncResponse(cMPResponse);
        } else {
            cmpLocalService.updateCMPTransactionStatus(transactionID, senderName, responseFromManager, MessageStatus.FAILED, errorInfo);
        }
        return responseFromManager;
    }

    private void handleSyncResponse(final CMPResponse cMPResponse) throws ResponseSignerException {
        try {
            final String transactionID = cMPResponse.getTransactionID();
            final String senderName = cMPResponse.getEntityName();
            final FailureResponseMessage failureResponseMessage = createFailureResponseMessage(cMPResponse);
            final String senderNonce = failureResponseMessage.getSenderNonce();
            final String errorInfo = cMPResponse.getErrorInfo();
            final CMPMessageEntity cMPMessageEntity = persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
            final byte[] signedResponseMessage = messageSignerService.signMessage(cMPResponse.getIssuerName(), failureResponseMessage);

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

    private FailureResponseMessage createFailureResponseMessage(final CMPResponse cMPResponse) throws CertificateException, IOException {

        final String sender = messageSignerService.getSenderFromSignerCert(cMPResponse.getIssuerName());
        final String recipientName = cMPResponse.getEntityName();
        final String transactionID = cMPResponse.getTransactionID();
        final byte[] protectionAlgorithm = cMPResponse.getProtectionAlgorithm();
        final byte[] responseFromManager = cMPResponse.getCmpResponse();

        final FailureResponseMessage failureResponseMessage = new FailureResponseMessage(responseFromManager);
        final List<X509Certificate> cMPextraCertificates =
                messageSignerService.buildCMPExtraCertsForResponseFromManager(cMPResponse.getIssuerName(), failureResponseMessage);
        final String senderNonce = failureResponseMessage.getSenderNonce();
        final String recipientNonce = failureResponseMessage.getReceipientNonce();

        failureResponseMessage.setProtectionAlgorithm(protectionAlgorithm);
        failureResponseMessage.createPKIHeader(sender, recipientName, senderNonce, recipientNonce, transactionID);
        failureResponseMessage.createPKIMessage(cMPextraCertificates);

        return failureResponseMessage;
    }

}
