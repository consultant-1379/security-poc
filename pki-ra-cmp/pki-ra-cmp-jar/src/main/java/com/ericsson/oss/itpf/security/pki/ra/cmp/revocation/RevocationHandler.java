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
package com.ericsson.oss.itpf.security.pki.ra.cmp.revocation;

import java.io.IOException;
import java.util.Date;
import java.util.List;

import javax.inject.Inject;
import javax.naming.InvalidNameException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.DateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateParseException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidCertificateVersionException;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DigitalSigningFailedException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.CMPRequestSigner;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request.dispatcher.RevocationServiceRequestDispatcher;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.SignedRevocationServiceRequest;

/**
 * This class is responsible for Sending Revocation Request.
 * 
 * @author tcsramc
 *
 */
public class RevocationHandler {

    @Inject
    PersistenceHandler persistenceHandler;

    @Inject
    RevocationServiceRequestDispatcher revocationServiceRequestDispatcher;

    @Inject
    Logger logger;

    @Inject
    InitialConfiguration initialConfiguration;

    @Inject
    CMPRequestSigner requestSigner;

    private static final String REVOCATIONREASON = "SUPERSEDED";
    private static final int REVOCATION_BATCH_LIMIT = 500;

    /**
     * This method is used to form Revocation request with all parameters required for manager to perform revocation Operation. Once Request building is done it is being signed by SignerCertificate
     * and sent to pki-manager in the form of signedXMLdata.
     * 
     * @param transactionId
     *            transactionID
     * @param subjectName
     *            entityName
     * @param issuerName
     *            issuer
     * @param certificateSerialNumber
     *            serialnumber of the certificate.
     * @throws MessageParsingException
     *             is thrown when Message parsing error occurs.
     * @throws CertificateParseException
     *             is thrown when Certificate parsing error occurs.
     * @throws InvalidCertificateVersionException
     *             is thrown if certificate version is invalid
     * @throws IOException
     *             is thrown if any i/o error occurs.
     * @throws DigitalSigningFailedException
     *             is thrown when failed to do digital signing for an xml
     */
    public void revoke(final String transactionId, final String subjectName, final String issuerName, final String certificateSerialNumber) throws MessageParsingException, CertificateParseException,
            InvalidCertificateVersionException, IOException, DigitalSigningFailedException {

        final RevocationRequest revocationRequest = build(transactionId, subjectName, issuerName, certificateSerialNumber);
        final byte[] signedXMLData = requestSigner.signRevocationRequest(revocationRequest);
        final SignedRevocationServiceRequest signedRevocationServiceRequest = new SignedRevocationServiceRequest();
        signedRevocationServiceRequest.setRevocationServiceRequest(signedXMLData);
        revocationServiceRequestDispatcher.dispatch(signedRevocationServiceRequest);
    }

    /**
     * This method is invoked by the Scheduler Bean whenever Timeout Occurs. It fetches records from the db based on Status and will send to Revoke API to revoke certificate.
     */
    public void revokeCertificateBasedOnStatus() {
        logger.debug("Entered into Revoke Certificates method which is invoked by timer");

        final List<CMPMessageEntity> revocationEntities = persistenceHandler.fetchToBeRevokedMessages(REVOCATION_BATCH_LIMIT);
        try {
            for (final CMPMessageEntity protocolMessageEntity : revocationEntities) {

                if (MessageStatus.TO_BE_REVOKED_NEW.equals(protocolMessageEntity.getStatus())) {
                    revokeNewCertificate(protocolMessageEntity);
                } else if (MessageStatus.TO_BE_REVOKED_OLD.equals(protocolMessageEntity.getStatus())) {
                    revokeOldCertificate(protocolMessageEntity);
                }
            }
        } catch (MessageParsingException | InvalidNameException | IOException exception) {
            logger.error("Error Occured While Revoking the certificate in timer");
            logger.debug("Error Occured While Revoking the certificate in timer ", exception);
        }

    }

    private RevocationRequest build(final String transactionId, final String subjectName, final String issuerName, final String certificateSerialNumber) throws MessageParsingException,
            CertificateParseException, InvalidCertificateVersionException, IOException {
        final CMPMessageEntity cMPMessageEntity = persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionId, subjectName);
        final Date modifiedDate = cMPMessageEntity.getModifyTime();
        final String invalidityDate = DateUtility.getDateinStringFormat(modifiedDate);
        return (new RevocationRequest()).setInvalidityDate(invalidityDate).setIssuerName(issuerName).setSerialNumber(certificateSerialNumber).setSubjectName(subjectName)
                .setTransactionId(transactionId).setRevocationReason(REVOCATIONREASON);
    }

    private void revokeOldCertificate(final CMPMessageEntity protocolMessageEntity) throws IOException, MessageParsingException, InvalidNameException {
        byte[] messageFromDB = protocolMessageEntity.getInitialMessage();
        revoke(protocolMessageEntity, messageFromDB);
    }

    private void revokeNewCertificate(final CMPMessageEntity protocolMessageEntity) throws IOException, MessageParsingException, InvalidNameException {
        byte[] messageFromDB = protocolMessageEntity.getResponseMessage();
        revoke(protocolMessageEntity, messageFromDB);
    }

    private void revoke(final CMPMessageEntity protocolMessageEntity, final byte[] messageFromDB) throws IOException, MessageParsingException, InvalidNameException {
        final String transactionID = protocolMessageEntity.getTransactionID();
        final String senderName = protocolMessageEntity.getSenderName();
        final String issuerName = CertificateUtility.getCertificateIssuer(messageFromDB);
        final String serialNumber = CertificateUtility.getCertificateSerialNumber(messageFromDB);

        if(isNullorEmpty(issuerName) || isNullorEmpty(serialNumber)) {
            logger.error("Unable to fetch the issuerName or serialNumber from cmpMessage, Changing the cmp message status to FAILED");
            protocolMessageEntity.setStatus(MessageStatus.FAILED);
            persistenceHandler.updateEntity(protocolMessageEntity);
            return;
        }

        revoke(transactionID, senderName, issuerName, serialNumber);
    }

    private boolean isNullorEmpty(final String str){
        return (str == null || str.trim().isEmpty());
    }
}
