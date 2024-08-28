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

import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.KeyUpdateResponseMessage;
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
 * This class handles Key update response sent from PKI-Manager, implements <code> ResponseHandler</code>. Message is extracted from modeled event and
 * saved into DB with status as
 * "wait for acknowledgement".
 * 
 * @author tcsdemi
 */
@ProtocolResponseType(Constants.TYPE_KEY_UPDATE_RESPONSE)
public class KeyUpdateResponseHandler implements ResponseHandler {

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
    public byte[] handle(final CMPResponse cMPResponse) throws ResponseSignerException {

        final String transactionID = cMPResponse.getTransactionID();
        final String senderName = cMPResponse.getEntityName();
        final byte[] keyUpdateResponseFromManager = cMPResponse.getCmpResponse();
        final String errorInfo = cMPResponse.getErrorInfo();

        logger.debug("Received KUP response with transaction id [{}]", transactionID);
        if (cMPResponse.getSyncResponse()) {
            logger.debug("Received SYNC KUP response with transaction id [{}]", transactionID);
            handleSyncResponse(cMPResponse);
        } else {
            cmpLocalService.updateCMPTransactionStatus(transactionID, senderName, keyUpdateResponseFromManager, MessageStatus.WAIT_FOR_ACK, errorInfo);
        }

        return keyUpdateResponseFromManager;
    }

    private void handleSyncResponse(final CMPResponse cMPResponse) throws ResponseSignerException {
        try {
            final String transactionID = cMPResponse.getTransactionID();
            final String senderName = cMPResponse.getEntityName();
            final KeyUpdateResponseMessage keyUpdateResponse = createKUPResponseMessage(cMPResponse);
            final String senderNonce = keyUpdateResponse.getSenderNonce();
            final String errorInfo = cMPResponse.getErrorInfo();
            final CMPMessageEntity cMPMessageEntity = persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
            final byte[] encodedCertificate = getCMPCertificate(keyUpdateResponse);
            logger.info("certificate present in the response message [{}] sender name [{}] transactionID[{}]", encodedCertificate, senderName, transactionID);            
            final byte[] signedResponseMessage = messageSignerService.signMessage(cMPResponse.getIssuerName(), keyUpdateResponse);
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

    private KeyUpdateResponseMessage createKUPResponseMessage(final CMPResponse cMPResponse) throws CertificateException, IOException {

        final String sender = messageSignerService.getSenderFromSignerCert(cMPResponse.getIssuerName());
        final String recipientName = cMPResponse.getEntityName();
        final String transactionID = cMPResponse.getTransactionID();
        final byte[] protectionAlgorithm = cMPResponse.getProtectionAlgorithm();
        final byte[] responseFromManager = cMPResponse.getCmpResponse();

        final KeyUpdateResponseMessage keyUpdateResponseMessage = new KeyUpdateResponseMessage(responseFromManager);
        final List<X509Certificate> cMPextraCertificates =
                messageSignerService.buildCMPExtraCertsForResponseFromManager(cMPResponse.getIssuerName(), keyUpdateResponseMessage);
        final String senderNonce = keyUpdateResponseMessage.getSenderNonce();
        final String recipientNonce = keyUpdateResponseMessage.getReceipientNonce();

        keyUpdateResponseMessage.setProtectionAlgorithm(protectionAlgorithm);
        keyUpdateResponseMessage.createPKIHeader(sender, recipientName, senderNonce, recipientNonce, transactionID);
        keyUpdateResponseMessage.createPKIMessage(cMPextraCertificates);

        return keyUpdateResponseMessage;
    }
    
    private byte[] getCMPCertificate(final KeyUpdateResponseMessage keyUpdateResponse) throws IOException {
   	 PKIMessage p = keyUpdateResponse.getPKIResponseMessage();
        final CertRepMessage ipMessage = CertRepMessage.getInstance(p.getBody().getContent());
        final CertResponse[] certResponses = ipMessage.getResponse();
        final CertResponse resp = certResponses[0];
        return resp.getCertifiedKeyPair().getCertOrEncCert().getCertificate().getX509v3PKCert().getEncoded();
   }
    
}
