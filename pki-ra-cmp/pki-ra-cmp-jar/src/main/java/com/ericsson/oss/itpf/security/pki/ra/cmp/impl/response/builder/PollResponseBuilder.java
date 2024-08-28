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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.builder;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.ResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.*;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderExceptionHelper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.model.PollResponseMessage;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.qualifiers.ProtocolResponseType;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.ResponseMessageSigningHelper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.CertificateEnrollmentStatusBuilder;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.CertificateEnrollmentStatusDispatcher;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.CertificateEnrollmentStatusUtility;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;
import com.ericsson.oss.itpf.security.pki.ra.model.edt.CertificateEnrollmentStatusType;
import com.ericsson.oss.itpf.security.pki.ra.model.events.CertificateEnrollmentStatus;

/**
 * This class implements ResponseBuilder. Builds Poll response for Poll request. Building response will vary based on :
 * <p>
 * In case Poll Response is to be built:<br>
 * 1. Building PKIHeader/PKIbody/PKIMessage <br>
 * 2. Signing the message.<br>
 * 3. Updating DB with the signed response and also status if necessary. <br>
 * <p>
 * In case IP/KUP is already available in DB:<br>
 * 1. Change the nonce of the stored responseMessage, since these were built based on IR/KUR and not the consecutive Poll request and built a new PKIHeader. 2. Sign the message<br>
 * 3. Updating DB with the signed response and also status if necessary.
 *
 * @author tcsdemi
 *
 */
@ProtocolResponseType(Constants.TYPE_POLL_RESPONSE)
public class PollResponseBuilder implements ResponseBuilder {

    @Inject
    ResponseMessageSigningHelper responseMessageSigningHelper;

    @Inject
    ConfigurationParamsListener cMPConfigurationListener;

    @Inject
    PersistenceHandler persistenceHandler;

    @Inject
    Logger logger;

    @Inject
    private CertificateEnrollmentStatusDispatcher certificateEnrollmentStatusDispatcher;

    @Inject
    private CertificateEnrollmentStatusBuilder certificateEnrollmentStatusBuilder;

    @Inject
    CertificateEnrollmentStatusUtility certificateEnrollmentStatusUtility;


    @Override
    public byte[] build(final RequestMessage pollRequestMessage, final String transactionID) throws ResponseBuilderException, InvalidInitialConfigurationException {

        byte[] signedResponse = null;
        CertificateEnrollmentStatus certificateEnrollmentStatus = null;
        final String senderName = pollRequestMessage.getSenderName();
        final CMPMessageEntity cMPMessageEntity = persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName);

        final MessageStatus status = cMPMessageEntity.getStatus();
        logger.info("Building response for poll request with Entity name [{}], Transaction ID[{}]", senderName, transactionID);
        logger.info("Message status from database[{}]", status);
        try {
            final String commonName = certificateEnrollmentStatusUtility.extractSubjectNameFromInitialMessage(cMPMessageEntity.getInitialMessage());

            switch (status) {
            case WAIT_FOR_ACK:
                logger.info("Either IP/KUP Message is received from Manager, hence fetching from DB responseMessage");
                signedResponse = signIPorKUPMessageFromDB(pollRequestMessage, cMPMessageEntity);
                certificateEnrollmentStatus = certificateEnrollmentStatusBuilder.build(commonName, pollRequestMessage.getIssuerName(), CertificateEnrollmentStatusType.CERTIFICATE_SENT);
                dispatchCertificateEnrollmentStatus(certificateEnrollmentStatus);
                break;

            case FAILED:
            case TO_BE_REVOKED_NEW:
                logger.info("Either IP/KUP or Error Message is received from Manager, hence fetching from DB responseMessage");
                signedResponse = signErrorOrIPorKUPMessageFromDB(pollRequestMessage, cMPMessageEntity);
                certificateEnrollmentStatus = certificateEnrollmentStatusBuilder.build(commonName, pollRequestMessage.getIssuerName(), CertificateEnrollmentStatusType.FAILURE);
                dispatchCertificateEnrollmentStatus(certificateEnrollmentStatus);
                break;

            default:
                logger.info("IP/KUP yet to receive from PKI-Manager, hence building pollResponse");
                signedResponse = buildPollResponse(pollRequestMessage, transactionID);
                break;
            }

        } catch (IOException ioException) {
            ResponseBuilderExceptionHelper.throwCustomException(ErrorMessages.IO_EXCEPTION, ioException);

        } catch (CertificateException certificateException) {
            ResponseBuilderExceptionHelper.throwCustomException(ErrorMessages.CERTIFICATE_IS_NULL, certificateException);
        } catch (MessageParsingException messageParsingException) {
            ResponseBuilderExceptionHelper.throwCustomException(messageParsingException);
        }
        return signedResponse;
    }

    private byte[] signErrorOrIPorKUPMessageFromDB(final RequestMessage pollRequestMessage, final CMPMessageEntity cMPMessageEntity)
            throws InvalidInitialConfigurationException, CertificateException, IOException {

        final String senderName = pollRequestMessage.getSenderName();
        final String transactionID = cMPMessageEntity.getTransactionID();

        final String recipientNonce = pollRequestMessage.getRecepientNonce();
        byte[] unSignedResponseFromPKIManager = cMPMessageEntity.getResponseMessage();

        final ResponseMessage updatedResponseWithRecipientNonce = changeRecipientNonceAndBuildNewPKIMessage(pollRequestMessage, unSignedResponseFromPKIManager, recipientNonce);
        updateResponse(senderName, transactionID, updatedResponseWithRecipientNonce.toByteArray());

        return responseMessageSigningHelper.signMessage(pollRequestMessage.getIssuerName(), updatedResponseWithRecipientNonce);
    }

    private byte[] signIPorKUPMessageFromDB(final RequestMessage pollRequestMessage, final CMPMessageEntity cMPMessageEntity)
            throws InvalidInitialConfigurationException, CertificateException, IOException {

        final String senderName = pollRequestMessage.getSenderName();
        final String transactionID = cMPMessageEntity.getTransactionID();
        final String recipientNonce = pollRequestMessage.getSenderNonce();
        final byte[] unSignedResponseFromPKIManager = cMPMessageEntity.getResponseMessage();
        final ResponseMessage updatedResponseWithRecipientNonce = changeRecipientNonceAndBuildNewPKIMessage(pollRequestMessage, unSignedResponseFromPKIManager, recipientNonce);
        final byte[] signedResponse = responseMessageSigningHelper.signMessage(pollRequestMessage.getIssuerName(), updatedResponseWithRecipientNonce);

        updateResponse(senderName, transactionID, signedResponse);

        return signedResponse;
    }

    private ResponseMessage changeRecipientNonceAndBuildNewPKIMessage(final RequestMessage pKIRequestMessage, final byte[] unSignedResponsePKIManager, final String recipientNonce)
            throws InvalidInitialConfigurationException, CertificateException, IOException {

        final ResponseMessage responseMessage = new PollResponseMessage(unSignedResponsePKIManager);
        final List<X509Certificate> cMPextraCertificates = responseMessageSigningHelper.buildCMPExtraCertsForResponseFromManager(pKIRequestMessage.getIssuerName(), responseMessage);
        final String sender = responseMessageSigningHelper.getSenderFromSignerCert(pKIRequestMessage.getIssuerName());
        final String recipient = pKIRequestMessage.getSenderName();
        final String senderNonce = responseMessage.getSenderNonce();
        final String transactionId = pKIRequestMessage.getBase64TransactionID();
        responseMessage.createPKIHeader(sender, recipient, senderNonce, recipientNonce, transactionId);
        responseMessage.createPKIMessage(cMPextraCertificates);
        responseMessage.setProtectionAlgorithm(pKIRequestMessage.getProtectAlgorithm().getEncoded());

        return responseMessage;
    }

    private void updateResponse(final String senderName, final String transactionID, final byte[] signedResponse) {
        final CMPMessageEntity protocolMessageEntity = persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
        final ResponseMessage responseMessage = new PollResponseMessage(signedResponse);
        final String senderNonce = responseMessage.getSenderNonce();
        protocolMessageEntity.setSenderNonce(senderNonce);
        protocolMessageEntity.setResponseMessage(signedResponse);
        persistenceHandler.updateEntity(protocolMessageEntity);
    }

    private byte[] buildPollResponse(final RequestMessage pollRequestMessage, final String transactionID) throws IOException, InvalidInitialConfigurationException, CertificateException {

        final PollResponseMessage pKIPollResponseMessage = new PollResponseMessage();
        logger.info("Creating Poll Response ");
        createPollResponseMessage(pollRequestMessage, transactionID, pKIPollResponseMessage);
        final byte[] signedPollResponseMessage = responseMessageSigningHelper.signMessage(pollRequestMessage.getIssuerName(), pKIPollResponseMessage);

        logger.info("Sending Polling response");
        return signedPollResponseMessage;

    }

    private void createPollResponseMessage(final RequestMessage pollRequestMessage, final String transactionID, final PollResponseMessage pKIPollResponseMessage) throws IOException {
        final int checkAfter = cMPConfigurationListener.getNodeWaitTimeBeforePollRequest();
        final String senderNonce = Base64EncodedIdGenerator.generate();
        final String recipientNonce = pollRequestMessage.getSenderNonce();
        final String recipient = pollRequestMessage.getSenderName();
        final String sender = responseMessageSigningHelper.getSenderFromSignerCert(pollRequestMessage.getIssuerName());
        final int certRequestId = pollRequestMessage.getRequestId();
        final byte[] encodedProtectionAlgorithm = pollRequestMessage.getProtectAlgorithm().getEncoded();
        final List<X509Certificate> cMPextraCertificates = responseMessageSigningHelper.addSignerCertandCertChainToCMPExtraCertificates(pollRequestMessage.getIssuerName());

        pKIPollResponseMessage.setProtectionAlgorithm(encodedProtectionAlgorithm);
        pKIPollResponseMessage.createPKIHeader(sender, recipient, senderNonce, recipientNonce, transactionID);
        pKIPollResponseMessage.createPollRepContent(certRequestId, checkAfter);
        pKIPollResponseMessage.createPKIBody(pKIPollResponseMessage.getPollRepContent());
        pKIPollResponseMessage.createPKIMessage(cMPextraCertificates);
        pKIPollResponseMessage.setIssuerName(pollRequestMessage.getIssuerName());
    }

    private void dispatchCertificateEnrollmentStatus(final CertificateEnrollmentStatus certificateEnrollmentStatus) {
        if (certificateEnrollmentStatus != null) {
            certificateEnrollmentStatusDispatcher.dispatch(certificateEnrollmentStatus);
        }
    }
}
