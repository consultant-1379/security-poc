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
package com.ericsson.oss.itpf.security.pki.ra.scep.processor;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.*;
import com.ericsson.oss.itpf.security.pki.common.scep.constants.ResponseStatus;
import com.ericsson.oss.itpf.security.pki.common.scep.model.ScepRequest;
import com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml.AttachedSignatureXMLBuilder;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DigitalSigningFailedException;
import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.scep.cryptoservice.CryptoService;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepRequestData;
import com.ericsson.oss.itpf.security.pki.ra.scep.event.sender.SignedScepRequestMessageSender;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.BadRequestException;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.PkiScepServiceException;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.entity.Pkcs7ScepRequestEntity;
import com.ericsson.oss.itpf.security.pkira.scep.event.SignedScepRequestMessage;

/**
 * This class persists the pkcs7ScepRequestData into database and sends the certificate request over ScepRequestChannel to PKI manager
 *
 * @author xtelsow
 */
public class PkcsRequestProcessor {

    @Inject
    private Logger logger;

    @Inject
    private PersistenceHandler peristanceHandler;

    @Inject
    private SignedScepRequestMessageSender requestMessageSender;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private CryptoService cryptoService;

    @Inject
    private ConfigurationListener configurationListener;

    /**
     * This method is used to persist data into the the database and sends the request over ScepRequestChannel channel to the PKI Manager.
     *
     * @param pkcs7ScepRequestData
     *            contains SCEP request data.
     * @param status
     *            is the status of request being processed.
     * @throws PkiScepServiceException
     *             is thrown for internal database issues.
     */

    public void processRequest(final Pkcs7ScepRequestData pkcs7ScepRequestData, final int status) throws PkiScepServiceException {
        logger.debug("In processRequest method of PkcsRequestProcessor");
        persistData(pkcs7ScepRequestData, status);
        final ScepRequest scepRequest = createScepRequest(pkcs7ScepRequestData);
        final byte[] digitallysignedScepRequest = buildSignedScepRequestMessage(scepRequest);
        dispatchScepRequestEvent(digitallysignedScepRequest);

        systemRecorder.recordEvent("PKI_RA_SCEP.REQUEST_SENT_TO_PKI_MANAGAR", EventLevel.COARSE, "PKIRASCEPService", "SCEP Enrollement and SCEP Client",
                "Certificate request has been forwarded to CA with the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
        logger.debug("End of processRequest method of PkcsRequestProcessor");
    }

    /**
     * This method persists the pkcs7ScepRequestData into Database.
     *
     * @param pkcs7ScepRequestData
     *            contains SCEP request data.
     * @param status
     *            is the status of request being processed.
     * @throw BadRequestException is thrown when PKCS Request with same Transaction Id with different Issuer and Subject name already exists.
     */
    private void persistData(final Pkcs7ScepRequestData pkcs7ScepRequestData, final int status) throws BadRequestException {

        logger.debug("In persistData method of class PkcsRequestProcessor");
        final String transactionId = pkcs7ScepRequestData.getTransactionId();
        final String subjectDN = pkcs7ScepRequestData.getSubjectName();
        final String issuerDN = pkcs7ScepRequestData.getIssuerName();

        try {
            final Pkcs7ScepRequestEntity pkcs7ScepRequestEntity = peristanceHandler.getPkcs7ScepRequestEntity(transactionId);
            if (pkcs7ScepRequestEntity != null) {
                if (subjectDN.equals(pkcs7ScepRequestEntity.getSubjectname()) && issuerDN.equals(pkcs7ScepRequestEntity.getIssuername())) {
                    final Pkcs7ScepRequestEntity updatePkcs7ScepRequestEntity = new Pkcs7ScepRequestEntity(transactionId, subjectDN, issuerDN, new Timestamp(System.currentTimeMillis()), null,
                            ResponseStatus.PENDING.getStatus(), null);
                    peristanceHandler.updatePkcs7ScepRequestEntity(updatePkcs7ScepRequestEntity);
                } else {
                    logger.error("PKCS Request with same transaction id with different Issuer and Subject name already exists in the db for the Transaction Id :"
                            + pkcs7ScepRequestData.getTransactionId() + " and the End Entity " + pkcs7ScepRequestData.getEndEntityName());
                    systemRecorder.recordError("PKI_RA_SCEP.TXN_ID_ALREADY_EXIST", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollment for End Entity",
                            "Duplicate transaction id with different Issuer and Subject name has been found for the Transaction Id :" + pkcs7ScepRequestData.getTransactionId()
                                    + " and the End Entity " + pkcs7ScepRequestData.getEndEntityName());
                    throw new BadRequestException(ErrorMessages.TRANSACTION_ALREADY_EXIST);
                }
            } else {
                final Pkcs7ScepRequestEntity createPkcs7ScepRequestEntity = new Pkcs7ScepRequestEntity(transactionId, subjectDN, issuerDN, new Timestamp(System.currentTimeMillis()), null, status,
                        null);
                peristanceHandler.persistPkcs7ScepRequestEntity(createPkcs7ScepRequestEntity);
            }
        } catch (PersistenceException e) {
            logger.error("PersistenceException while persisting the PKCS7SCEPRequest data in scep database with the Transaction Id :" + pkcs7ScepRequestData.getTransactionId()
                    + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
            systemRecorder.recordError(
                    "PKI_RA_SCEP.PERSIST_REQUEST_ERROR",
                    ErrorSeverity.ERROR,
                    "PkcsRequestProcessor",
                    "SCEP Enrollment for End Entity",
                    "DB failure while processing the PKCS7SCEPRequest for the Transaction Id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                            + pkcs7ScepRequestData.getEndEntityName());
            throw new PkiScepServiceException(ErrorMessages.REQUEST_PROCESS_FAILURE);
        }

    }

    private ScepRequest createScepRequest(final Pkcs7ScepRequestData pkcs7ScepRequestData) {
        final ScepRequest scepRequest = new ScepRequest();
        scepRequest.setCsr(pkcs7ScepRequestData.getPkcsReqinfo());
        scepRequest.setTransactionId(pkcs7ScepRequestData.getTransactionId());
        return scepRequest;
    }

    private void dispatchScepRequestEvent(final byte[] scepRequest) {
        final SignedScepRequestMessage signedScepRequestMessage = new SignedScepRequestMessage();
        signedScepRequestMessage.setScepRequest(scepRequest);
        requestMessageSender.sendMessageToScepRequestChannel(signedScepRequestMessage);
    }

    /**
     * This method is used to build the digitally singed Scep Request Message.
     * 
     * @return byte[] digitally signed scep request message in the form of byte array.
     */
    private byte[] buildSignedScepRequestMessage(final ScepRequest scepRequest) throws PkiScepServiceException {
        logger.info("Signing scep request message");
        byte[] digitallysignedScepRequest = null;
        String signerCertificateAliasName = null;
        try {
            signerCertificateAliasName = configurationListener.getScepRAInfraCertAliasName();
            final X509Certificate signerCertificate = (X509Certificate) cryptoService.readCertificate(signerCertificateAliasName, false);
            final PrivateKey signerPrivateKey = cryptoService.readPrivateKey(signerCertificateAliasName);
            digitallysignedScepRequest = AttachedSignatureXMLBuilder.build(signerCertificate, signerPrivateKey, scepRequest);
        } catch (PkiScepServiceException e) {
            logger.error("Failed to read Certificate/Privatekey from Keystore with the alias name:" + signerCertificateAliasName);
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PKIRASCEPService_SecureCommunication.XMLSigner", "Failed to read private key/certifcate from keystore with aliasname "
                    + signerCertificateAliasName, "PKIRASCEPService.XMLSigning", ErrorSeverity.CRITICAL, "FAILURE");
            throw new PkiScepServiceException(ErrorMessages.FAIL_TO_SIGN_REQUEST_MESSAGE);
        } catch (DigitalSigningFailedException e) {
            logger.error(ErrorMessages.FAIL_TO_SIGN_REQUEST_MESSAGE.concat(e.getMessage()));
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PKIRASCEPService_SecureCommunication.XMLSigner", ErrorMessages.FAIL_TO_SIGN_REQUEST_MESSAGE, "PKIRASCEPService.XMLSigning",
                    ErrorSeverity.CRITICAL, "FAILURE");
            throw new PkiScepServiceException(ErrorMessages.FAIL_TO_SIGN_REQUEST_MESSAGE);
        } catch (BadRequestException e) {
            logger.error(ErrorMessages.FAIL_TO_SIGN_REQUEST_MESSAGE, "Invalid alias name given for Scep RA infrastructure certificate");
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PKIRASCEPService_SecureCommunication.XMLSigner", "Invalid alias name given for Scep RA infrastructure certificate",
                    "PKIRASCEPService.XMLSigning", ErrorSeverity.CRITICAL, "FAILURE");
            throw new PkiScepServiceException(ErrorMessages.FAIL_TO_SIGN_REQUEST_MESSAGE);
        }
        logger.info("Created the Digitally Signed Scep Request Message.");
        return digitallysignedScepRequest;
    }
}
