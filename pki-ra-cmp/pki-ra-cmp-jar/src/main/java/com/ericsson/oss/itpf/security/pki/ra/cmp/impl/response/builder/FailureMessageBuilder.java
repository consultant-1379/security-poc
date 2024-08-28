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
import java.security.cert.X509Certificate;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.FailureResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ProtectionEncodingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ResponseSignerException;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Base64EncodedIdGenerator;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderExceptionHelper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.ResponseMessageSigningHelper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.*;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;
import com.ericsson.oss.itpf.security.pki.ra.model.edt.CertificateEnrollmentStatusType;
import com.ericsson.oss.itpf.security.pki.ra.model.events.CertificateEnrollmentStatus;

/**
 * This class is used to build Failure message to be sent to entity, in case of any exception for eg: validation Failure.This class implements ResponseBuilder.
 * 
 * @author tcsdemi
 *
 */
public class FailureMessageBuilder implements ResponseBuilder {

    @Inject
    Logger logger;

    @Inject
    PersistenceHandler persistenceHandler;

    @Inject
    ResponseMessageSigningHelper responseMessageSigningHelper;

    @Inject
    private CertificateEnrollmentStatusDispatcher certificateEnrollmentStatusDispatcher;

    @Inject
    private CertificateEnrollmentStatusBuilder certificateEnrollmentStatusBuilder;

    @Inject
    CertificateEnrollmentStatusUtility certificateEnrollmentStatusUtility;


    public byte[] build(final RequestMessage pKIRequestMessage, final String errorMessage) throws ResponseBuilderException {

        byte[] signedFailureResponse = null;

        try {
            final FailureResponseMessage failureResponseMessage = new FailureResponseMessage(pKIRequestMessage, errorMessage);
            final String senderName = pKIRequestMessage.getSenderName();
            final String transactionID = pKIRequestMessage.getBase64TransactionID();
            createFailureResponseMessage(pKIRequestMessage, failureResponseMessage);
            signedFailureResponse = responseMessageSigningHelper.signMessage(pKIRequestMessage.getIssuerName(), failureResponseMessage);
            final CMPMessageEntity protocolMessageEntity = createMessageEntity(senderName, transactionID, signedFailureResponse);

            if (protocolMessageEntity != null) {
                if (pKIRequestMessage.getSubjectName() == null || pKIRequestMessage.getSubjectName().isEmpty()) {
                    pKIRequestMessage.setSubjectName(certificateEnrollmentStatusUtility.extractSubjectNameFromInitialMessage(protocolMessageEntity.getInitialMessage()));
                }
                final CertificateEnrollmentStatus certificateEnrollmentStatus = certificateEnrollmentStatusBuilder
                        .build(pKIRequestMessage.getSubjectName(), pKIRequestMessage.getIssuerName(), CertificateEnrollmentStatusType.FAILURE);
                if (certificateEnrollmentStatus != null) {
                    certificateEnrollmentStatusDispatcher.dispatch(certificateEnrollmentStatus);
                }
                persistenceHandler.updateEntity(protocolMessageEntity);
                logger.warn(
                        "DB Record with TransactionID: {} and SenderName: {} is not present in DB. Reason being, validation must have failed for IR/KUR (NOTE: message is persisted in DB only when validation is successfull)",
                        transactionID, senderName);
            }
        } catch (IOException ioException) {
            ResponseBuilderExceptionHelper.throwCustomException(ioException);

        } catch (InvalidInitialConfigurationException initialConfigurationException) {
            ResponseBuilderExceptionHelper.throwCustomException(initialConfigurationException);

        } catch (ProtectionEncodingException protectionEncodingException) {
            ResponseBuilderExceptionHelper.throwCustomException(protectionEncodingException);

        } catch (ResponseSignerException responseSignerException) {
            ResponseBuilderExceptionHelper.throwCustomException(responseSignerException);
        }

        logger.info("Signed Error response");
        return signedFailureResponse;
    }

    private CMPMessageEntity createMessageEntity(final String senderName, final String transactionID, final byte[] signedResponse) {

        final CMPMessageEntity protocolMessageEntity = persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
        final String dEREncodedSenderNonce = new FailureResponseMessage(signedResponse).getSenderNonce();

        if (protocolMessageEntity != null) {
            protocolMessageEntity.setResponseMessage(signedResponse);
            protocolMessageEntity.setSenderNonce(dEREncodedSenderNonce);
            protocolMessageEntity.setStatus(MessageStatus.FAILED);
            logger.info("DB record with TransactionId: {} and SenderName: {} is updated with Status as FAILED and a failure message is sent back to entity.", transactionID, senderName );
        }
        return protocolMessageEntity;
    }

    private void createFailureResponseMessage(final RequestMessage pKIRequestMessage, final FailureResponseMessage failureResponseMessage) throws IOException {

        final String issuer = responseMessageSigningHelper.getSenderFromSignerCert(pKIRequestMessage.getIssuerName());
        final String senderNonce = Base64EncodedIdGenerator.generate();
        final String recipientNonce = pKIRequestMessage.getSenderNonce();
        final String recipient = pKIRequestMessage.getSenderName();
        final List<X509Certificate> cmpExtraCertificates = responseMessageSigningHelper.addSignerCertandCertChainToCMPExtraCertificates(pKIRequestMessage.getIssuerName());
        final byte[] encodedProtectionAlgorithm = pKIRequestMessage.getProtectAlgorithm().getEncoded();

        failureResponseMessage.setProtectionAlgorithm(encodedProtectionAlgorithm);
        failureResponseMessage.createErrorMsgContent();
        failureResponseMessage.createPKIHeader(issuer, recipient, senderNonce, recipientNonce, pKIRequestMessage.getBase64TransactionID());
        failureResponseMessage.createPKIBody(failureResponseMessage.getErrorMsgContent());
        failureResponseMessage.createPKIMessage(cmpExtraCertificates);
        failureResponseMessage.setIssuerName(pKIRequestMessage.getIssuerName());
    }

}
