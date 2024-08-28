/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
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
import javax.naming.InvalidNameException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.CMPRequestType;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.*;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Base64EncodedIdGenerator;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DigitalSigningFailedException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderExceptionHelper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.model.PKIConfResponseMessage;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.qualifiers.ProtocolResponseType;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.CertConfStatusUtil;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.ResponseMessageSigningHelper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.instrumentation.CMPInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.*;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.RevocationHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.RevocationHelper;
import com.ericsson.oss.itpf.security.pki.ra.model.edt.CertificateEnrollmentStatusType;
import com.ericsson.oss.itpf.security.pki.ra.model.events.CertificateEnrollmentStatus;

/**
 * This class implements ResponseBuilder. Builds PKIconf for Certificate confirmation request. Building response consists of: <br>
 * 1. Building PKIHeader/PKIbody/PKIMessage.<br>
 * 2. Signing the message.<br>
 * 3. Updating DB with the signed response and also status is necessary. <br>
 *
 * @author tcsdemi
 *
 */
@ProtocolResponseType(Constants.TYPE_PKI_CONF)
public class PKIConfResponseBuilder implements ResponseBuilder {

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    PersistenceHandler persistanceHandler;

    @Inject
    ResponseMessageSigningHelper responseMessageSigningHelper;

    @Inject
    RevocationHelper revocationHelper;

    @Inject
    RevocationHandler revocationHandler;

    @Inject
    CMPInstrumentationBean cmpInstrumentationBean;

    @Inject
    private CertificateEnrollmentStatusDispatcher certificateEnrollmentStatusDispatcher;

    @Inject
    private CertificateEnrollmentStatusBuilder certificateEnrollmentStatusBuilder;

    @Inject
    CertificateEnrollmentStatusUtility certificateEnrollmentStatusUtility;

    /**
     * This method is used to buildPKIConf ResponseMessage based on the certconfirm message sent by the node. For IR Revoke() method is called if CertConfirm status is "Rejected". incase of KUR
     * Revoke() is called to revoke Old certificate in case of CertConf "Accepted" and to revoke new certificate in case of CertConf "Rejected".
     */
    public byte[] build(final RequestMessage pKICertConfRequestmessage, final String transactionID) throws ResponseBuilderException {

        byte[] signedPKIConfResponseMessage = null;
        CertificateEnrollmentStatus certificateEnrollmentStatus = null;
        try {

            logger.info("Creating PKIConf response message");

            final PKIConfResponseMessage pKIConfResponseMessage = new PKIConfResponseMessage();
            final MessageStatus certConfStatus = CertConfStatusUtil.get(pKICertConfRequestmessage);
            final String senderName = pKICertConfRequestmessage.getSenderName();
            final byte[] messageFromDB = getRequestOrResponseFromDB(certConfStatus, senderName, transactionID);
            final String serialNumber = CertificateUtility.getCertificateSerialNumber(messageFromDB);
            final String issuerName = CertificateUtility.getCertificateIssuer(messageFromDB);

            createpKIConfResponseMessage(pKICertConfRequestmessage, transactionID, pKIConfResponseMessage);
            signedPKIConfResponseMessage = responseMessageSigningHelper.signMessage(pKICertConfRequestmessage.getIssuerName(), pKIConfResponseMessage);

            final CMPMessageEntity protocolMessageEntity = createMessageEntity(pKICertConfRequestmessage, transactionID, signedPKIConfResponseMessage);
            persistanceHandler.updateEntity(protocolMessageEntity);

            final CMPMessageEntity messageEntity = persistanceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
            if ((messageEntity.getRequestType().equalsIgnoreCase(CMPRequestType.KEY_UPDATE_REQUEST.toString()))
                    || (messageEntity.getRequestType().equalsIgnoreCase(CMPRequestType.INITIALIZATION_REQUEST.toString()) && MessageStatus.TO_BE_REVOKED
                            .equals(certConfStatus))) {
                revocationHelper.updateRevocationStatus(pKICertConfRequestmessage);
                revocationHandler.revoke(transactionID, senderName, issuerName, serialNumber);
            }
            final String subjectName = certificateEnrollmentStatusUtility.extractSubjectNameFromInitialMessage(protocolMessageEntity.getInitialMessage());

            if (certConfStatus == MessageStatus.DONE) {
                certificateEnrollmentStatus = certificateEnrollmentStatusBuilder.build(subjectName, pKICertConfRequestmessage.getIssuerName(),
                        CertificateEnrollmentStatusType.SUCCESS);
            } else if (certConfStatus == MessageStatus.TO_BE_REVOKED) {
                certificateEnrollmentStatus = certificateEnrollmentStatusBuilder.build(subjectName, pKICertConfRequestmessage.getIssuerName(),
                        CertificateEnrollmentStatusType.FAILURE);
            }
            if (certificateEnrollmentStatus != null) {
            certificateEnrollmentStatusDispatcher.dispatch(certificateEnrollmentStatus);
            }

        } catch (IOException | InvalidInitialConfigurationException | ProtectionEncodingException | ResponseSignerException | MessageParsingException | InvalidNameException
                | DigitalSigningFailedException exception) {
            ResponseBuilderExceptionHelper.throwCustomException(exception);
        }
        logger.info("Created PKIConf response message");

        systemRecorder.recordSecurityEvent(pKICertConfRequestmessage.getSenderName(), "CMP_SERVICE", "Issue/Re-Issue credential to network element", "CMP_SERVICE.ENROLLMENT_FINISHED",
                ErrorSeverity.INFORMATIONAL, "SUCCESS");

        return signedPKIConfResponseMessage;

    }

    private byte[] getRequestOrResponseFromDB(final MessageStatus certConfStatus, final String senderName, final String transactionID) {
        byte[] messageFromDB = null;
        final CMPMessageEntity protocolMessageEntity = persistanceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
        switch (certConfStatus) {
        case DONE:
            cmpInstrumentationBean.setEnrollmentSuccess();
            messageFromDB = protocolMessageEntity.getInitialMessage();
            break;

        case TO_BE_REVOKED:
            messageFromDB = protocolMessageEntity.getResponseMessage();
            break;

        default:
            logger.info("Certificate need not be revoked, since status could be DONE for IR");
            break;
        }
        return messageFromDB;
    }

    private CMPMessageEntity createMessageEntity(final RequestMessage pKICertConfRequestmessage, final String transactionID, final byte[] signedIPResponseMessage) {
        final String senderName = pKICertConfRequestmessage.getSenderName();
        final MessageStatus messageStatus = CertConfStatusUtil.get(pKICertConfRequestmessage);
        final CMPMessageEntity protocolMessageEntity = persistanceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
        protocolMessageEntity.setResponseMessage(signedIPResponseMessage);
        protocolMessageEntity.setStatus(messageStatus);
        return protocolMessageEntity;
    }

    private void createpKIConfResponseMessage(final RequestMessage pKICertConfRequestmessage, final String transactionID, final PKIConfResponseMessage pKIConfResponseMessage) throws IOException {
        final String issuer = responseMessageSigningHelper.getSenderFromSignerCert(pKICertConfRequestmessage.getIssuerName());
        final String senderNonce = Base64EncodedIdGenerator.generate();
        final String recipientNonce = pKICertConfRequestmessage.getSenderNonce();
        String recipient = null;
        if (pKICertConfRequestmessage.getSenderName() == null || pKICertConfRequestmessage.getSenderName().trim().isEmpty()) {
            logger.info("SenderName in CertificateConfirmation Request message is Null.Proceeding to fetch entity based on TransactionID");
            final CMPMessageEntity protocolMessageEntity = persistanceHandler.fetchEntityByTransactionID(transactionID);
            recipient = protocolMessageEntity.getSenderName();
        } else {
            recipient = pKICertConfRequestmessage.getSenderName();
        }
        final byte[] encodedProtectionAlgorithm = pKICertConfRequestmessage.getProtectAlgorithm().getEncoded();
        final List<X509Certificate> cMPextraCertificates = responseMessageSigningHelper.addSignerCertandCertChainToCMPExtraCertificates(pKICertConfRequestmessage.getIssuerName());

        pKIConfResponseMessage.setProtectionAlgorithm(encodedProtectionAlgorithm);
        pKIConfResponseMessage.createPKIHeader(issuer, recipient, senderNonce, recipientNonce, transactionID);
        pKIConfResponseMessage.createPKIBody(null);
        pKIConfResponseMessage.createPKIMessage(cMPextraCertificates);
        pKIConfResponseMessage.setIssuerName(pKICertConfRequestmessage.getIssuerName());
    }

}