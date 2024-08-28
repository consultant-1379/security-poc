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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.util.Iterator;

import javax.inject.Inject;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.MessageType;
import com.ericsson.oss.itpf.security.pki.ra.scep.cryptoservice.CryptoService;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.IssuerAndSubjectName;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepRequestData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.*;
import com.ericsson.oss.itpf.security.pki.ra.scep.validator.AlgorithmValidator;

/**
 * This class processes the Enveloped Data present in the PKCSReq or GetCertInitial Messages.
 *
 * @author xshaeru
 */
public class EnvelopedDataProcessor {

    @Inject
    private Logger logger;

    @Inject
    private AlgorithmValidator algorithmValidator;

    @Inject
    private CryptoService cryptoService;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method extracts the recipientInformation and calls the appropriate methods to decrypt the content.
     *
     * @param signedData
     *            is the asn1 SingedData of pkcs#7 message.
     * @param caName
     *            is the alias name to read the content from the key store.
     * @param pkcs7ScepRequestData
     *            is the PKCS7 request holder for SCEP request
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     * @throws BadRequestException
     *             is thrown while processing the invalid request message.
     */

    public void extractEnvelopedData(final SignedData signedData, final String caName, final Pkcs7ScepRequestData pkcs7ScepRequestData)
            throws PkiScepServiceException, BadRequestException {
        logger.debug("extractEnvelopedData method of EnvelopedDataProcessor");

        if (signedData.getEncapContentInfo().getContentType().equals(CMSObjectIdentifiers.data)) {
            final ASN1OctetString asn1OctetString = (ASN1OctetString) signedData.getEncapContentInfo().getContent();
            final ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(asn1OctetString.getOctets()));
            ASN1Sequence asn1Sequence = null;
            try {
                asn1Sequence = (ASN1Sequence) asn1InputStream.readObject();
                final ContentInfo contentInfo = ContentInfo.getInstance(asn1Sequence);
                if (contentInfo.getContentType().equals(CMSObjectIdentifiers.envelopedData)) {
                    final CMSEnvelopedData cmsEnvelopedData = new CMSEnvelopedData(contentInfo.getEncoded());
                    final RecipientInformation recipientInformation = extractRecipientInfo(cmsEnvelopedData, pkcs7ScepRequestData);
                    final MessageType messageType = MessageType.getNameByValue(pkcs7ScepRequestData.getMessageType());
                    switch (messageType) {
                        case PKCSREQ:
                            extractCSR(recipientInformation, caName, pkcs7ScepRequestData);
                            break;
                        case GETCERTINITIAL:
                            extractIssuerAndSubjectName(recipientInformation, caName, pkcs7ScepRequestData);
                            break;
                        case GETCERT:
                        case GETCRL:
                            logger.error("Un implemented Message type :" + messageType + " in request with the transaction id :"
                                    + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
                            systemRecorder.recordError("PKI_RA_SCEP.UNIMPLEMENTED_MESSAGE_TYPE", ErrorSeverity.ERROR, "SCEP Client",
                                    "SCEP Enrollement for End Entity",
                                    "Un supported Message type :" + messageType + " in request with the transaction id :"
                                            + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                                            + pkcs7ScepRequestData.getEndEntityName());
                            throw new NotImplementedMsgTypeException(ErrorMessages.MESSAGE_TYPE_NOT_IMPLEMENTED);
                        default:
                            logger.error("Un supported Message type :" + messageType + " in request with the transaction id :"
                                    + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
                            systemRecorder.recordError("PKI_RA_SCEP.UNSUPPORTED_MESSAGE_TYPE", ErrorSeverity.ERROR, "SCEP Client",
                                    "SCEP Enrollement for End Entity",
                                    "Un supported Message type :" + messageType + " in request with the transaction id :"
                                            + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                                            + pkcs7ScepRequestData.getEndEntityName());
                            throw new UnSupportedMsgTypeException(ErrorMessages.MESSAGE_TYPE_UNSUPPORTED);

                    }
                } else {
                    logger.error("Content type should be enveloped data in the content info of request with the transaction id :"
                            + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
                    systemRecorder
                            .recordError("PKI_RA_SCEP.INVALID_CONTENT_TYPE", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollement for End Entity",
                                    "Invalid content type for enveloped data in enrollment request with the transaction id :"
                                            + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                                            + pkcs7ScepRequestData.getEndEntityName());
                    throw new PkiScepServiceException(ErrorMessages.INVALID_CONTENT_TYPE_FOR_ENVELOPEDATA);
                }
            } catch (CMSException | IOException e) {
                logger.error("Failed to process Enveloped data in request with the transaction id :" + pkcs7ScepRequestData.getTransactionId()
                        + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
                systemRecorder.recordError("PKI_RA_SCEP.ENVELOPED_DATA_PROCESS_FAILED", ErrorSeverity.ERROR, "SCEP Client",
                        "SCEP Enrollement for End Entity", "Failed to process Enveloped data in enrollment request with the transaction id :"
                                + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
                throw new PkiScepServiceException(ErrorMessages.REQUEST_PROCESS_FAILURE);
            } finally {
                closeInputStream(asn1InputStream, pkcs7ScepRequestData);
            }
        } else {
            logger.error("Content Type should be data in the content info of PKCS7 request with the transaction id :"
                    + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName()

            );
            systemRecorder.recordError("PKI_RA_SCEP.INVALID_CONTENT_TYPE", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollement for End Entity",
                    "Invalid content type in the content info of PKCS7 request with the transaction id :" + pkcs7ScepRequestData.getTransactionId()
                            + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
            throw new PkiScepServiceException(ErrorMessages.INVALID_CONTENT_TYPE_FOR_DATA);
        }
        logger.debug("End of extractEnvelopedData method of EnvelopedDataProcessor");

    }

    /**
     * extractRecipientInfo accepts CMSEnvelopedData and fetches RecipientInformation and stores IssuerDN , IssuerSerial Number and
     * KeyEncryptionAlgorithmIdentifier.
     *
     * @param cmsEnvelopedData
     *            is the pkcs#7 CMSEnvelopedData from which the recipient info is extracted.
     * @param pkcs7ScepRequestData
     *            which holds the data of PKCSreq to be required to generate Response.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     * @throws BadRequestException
     *             is thrown if any invalid request.
     */
    private RecipientInformation extractRecipientInfo(final CMSEnvelopedData cmsEnvelopedData, final Pkcs7ScepRequestData pkcs7ScepRequestData)
            throws PkiScepServiceException, BadRequestException {
        logger.debug("extractRecipientInfo of EnvelopedDataProcessor");
        RecipientInformation recipientInformation = null;
        final String encryprtionAlgOid = cmsEnvelopedData.getEncryptionAlgOID();
        if (algorithmValidator.isSupportedAlgorithm(encryprtionAlgOid, "CmsEnvelopedData Encyrption", AlgorithmType.SYMMETRIC_KEY_ALGORITHM)) {
            pkcs7ScepRequestData.setContentEncryptionAlgOid(cmsEnvelopedData.getEncryptionAlgOID());
        } else {
            logger.error("CmsEnvelopedData Encyrption alogrithm with oid" + cmsEnvelopedData.getEncryptionAlgOID()
                    + " in request with the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                    + pkcs7ScepRequestData.getEndEntityName() + " is not supported.");
            systemRecorder.recordSecurityEvent("SCEP Client", "EnvelopedDataProcessor",
                    "CmsEnvelopedData Encyrption alogrithm with oid" + cmsEnvelopedData.getEncryptionAlgOID()
                            + " in request with the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                            + pkcs7ScepRequestData.getEndEntityName() + " is not supported.",
                    "Un Supported Algorithm", ErrorSeverity.ERROR, "FAILURE");
            throw new UnSupportedAlgException(ErrorMessages.UNSUPPORTED_ENCRYPTION_ALGORITHM_IN_CMSSIGNEDDATA);
        }

        final RecipientInformationStore recipientInformationStore = cmsEnvelopedData.getRecipientInfos();
        final Iterator<?> recipiterator = recipientInformationStore.getRecipients().iterator();
        while (recipiterator.hasNext()) {
            recipientInformation = (RecipientInformation) recipiterator.next();
            pkcs7ScepRequestData.setRecipientInformation(recipientInformation);
            final String encryptionAlgOID = recipientInformation.getKeyEncryptionAlgOID();
            if (!algorithmValidator.isSupportedAlgorithm(encryptionAlgOID, "RecipientInformation Key Encryption",
                    AlgorithmType.ASYMMETRIC_KEY_ALGORITHM)) {
                logger.error("RecipientInformation Key Encryption Alogrithm with oid " + encryptionAlgOID + " in request with the transaction id :"
                        + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName()
                        + " is not supported.");
                systemRecorder.recordSecurityEvent("SCEP Client", "EnvelopedDataProcessor",
                        "RecipientInformation Key Encryption Alogrithm with oid " + encryptionAlgOID + " in request with the transaction id :"
                                + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName()
                                + " is not supported.",
                        "Un Supported Algorithm", ErrorSeverity.ERROR, "FAILURE");
                throw new UnSupportedAlgException(ErrorMessages.UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM_IN_RECIPIENTINFO);
            }
            final KeyTransRecipientId keyTransRecipientId = (KeyTransRecipientId) recipientInformation.getRID();
            if (keyTransRecipientId != null) {
                pkcs7ScepRequestData.setIssuerName(keyTransRecipientId.getIssuer().toString());
            } else {
                logger.error("KeyTransRecipientId is null in RecipientInformationStore in request with the transaction id :"
                        + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
                systemRecorder.recordError("PKI_RA_SCEP.KEYTRANSRECIPIENTID_NULL", ErrorSeverity.ERROR, "SCEP Client",
                        "SCEP Enrollement for End Entity",
                        "KeyTransRecipientId is null in RecipientInformationStore in request with the transaction id :"
                                + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
                throw new BadRequestException(ErrorMessages.EMPTY_KEYTRANSRECIPIENTID);
            }
        }
        logger.debug("End of extractRecipientInfo of EnvelopedDataProcessor");
        return recipientInformation;

    }

    /**
     * This method decrypts the content in the Enveloped Data of PKCSReq or GetCertInitial message
     *
     * @param RecipientInformation
     *            is RecipientInformation of EnvelopedData from which the content is decrypted.
     * @param caName
     *            is the alias name to read the content from the key store
     * @param isGetCertInitialReq
     *            is the flag to identify the log level either warning or error when decryption of content failed.
     * @return byte[] is the decrypted content.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     */
    private byte[] decryptContent(final RecipientInformation recipientInformation, final String caName, final boolean isGetCertInitialReq)
            throws PkiScepServiceException {
        if (recipientInformation != null) {
            try {
                final PrivateKey privateKey = cryptoService.readPrivateKey(caName);
                final JceKeyTransEnvelopedRecipient jceKeyTransEnvelopedRecipient = new JceKeyTransEnvelopedRecipient(privateKey);
                final byte[] decryptedContent = recipientInformation.getContent(jceKeyTransEnvelopedRecipient);
                return decryptedContent;
            } catch (final CMSException e) {
                logger.debug("Error occured while decrypting the envelopedData", e);
                if (isGetCertInitialReq) {
                    logger.warn("Unable to extract Dec Bytes" + e.getMessage());
                } else {
                    logger.error("Unable to extract Dec Bytes" + e.getMessage());
                }
                throw new PkiScepServiceException(ErrorMessages.FAIL_TO_DECRYPT);
            }
        } else {
            logger.error("Recipient Information is null in EnvelopedData");
            throw new PkiScepServiceException(ErrorMessages.FAIL_TO_DECRYPT);
        }

    }

    /**
     * It extracts CSR from RecipientInfo.
     *
     * @param RecipientInformation
     *            is RecipientInformation of EnvelopedData from which the CSR is decrypted.
     * @param caName
     *            is the alias name to read the content from the key store.
     * @param pkcs7ScepRequestData
     *            which holds the data of PKCSreq to be required to generate Response.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     */

    private void extractCSR(final RecipientInformation recipientInformation, final String caName, final Pkcs7ScepRequestData pkcs7ScepRequestData)
            throws PkiScepServiceException, BadRequestException {

        PKCS10CertificationRequest certRequest;
        try {
            final byte[] decryptedContent = decryptContent(recipientInformation, caName, false);
            certRequest = new PKCS10CertificationRequest(decryptedContent);
            final JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest = new JcaPKCS10CertificationRequest(certRequest);
            final PublicKey publicKey = jcaPKCS10CertificationRequest.getPublicKey();
            pkcs7ScepRequestData.setPublicKey(publicKey);
            pkcs7ScepRequestData.setPkcsReqinfo(decryptedContent);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Algorithm not found while reading public key from CSR of PKCSRequest with the transaction id :"
                    + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
            logger.debug("Algorithm not found while reading public key from CSR of PKCSRequest with the transaction id :"
                    + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName(), e);
            systemRecorder.recordSecurityEvent("SCEP Client",
                    "EnvelopedDataProcessor", "Algorithm not found while reading public key from CSR with the transaction id :"
                            + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName(),
                    "Invalid Public Key", ErrorSeverity.ERROR, "FAILURE");
            throw new PkiScepServiceException(ErrorMessages.REQUEST_PROCESS_FAILURE);
        } catch (IOException e) {
            logger.error("Failure reading public key from CSR of PKCSRequest with the transaction id :" + pkcs7ScepRequestData.getTransactionId()
                    + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
            logger.debug("Failure reading public key from CSR of PKCSRequest with the transaction id :" + pkcs7ScepRequestData.getTransactionId()
                    + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName(), e);
            systemRecorder.recordSecurityEvent("SCEP Client",
                    "EnvelopedDataProcessor", "Failed to read public key from CSR with the transaction id :" + pkcs7ScepRequestData.getTransactionId()
                            + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName(),
                    "Public key reading failure", ErrorSeverity.ERROR, "FAILURE");
            throw new BadRequestException(ErrorMessages.INVALID_CSR);
        } catch (InvalidKeyException e) {
            logger.error("Invalid public key from CSR of PKCSRequest with the transaction id :" + pkcs7ScepRequestData.getTransactionId()
                    + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
            logger.debug("Invalid public key from CSR of PKCSRequest with the transaction id :" + pkcs7ScepRequestData.getTransactionId()
                    + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName(), e);
            systemRecorder.recordSecurityEvent(
                    "SCEP Client", "EnvelopedDataProcessor", "Invalid public key from CSR with the transaction id :"
                            + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName(),
                    "Invalid public key", ErrorSeverity.ERROR, "FAILURE");
            throw new BadRequestException(ErrorMessages.INVALID_CSR);
        } catch (PkiScepServiceException e) {
            logger.error("Failure in decrypting of CSR from PKCSRequest with the transaction id :" + pkcs7ScepRequestData.getTransactionId()
                    + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
            logger.debug("Failure in decrypting of CSR from PKCSRequest with the transaction id :" + pkcs7ScepRequestData.getTransactionId()
                    + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName(), e);
            systemRecorder.recordSecurityEvent(
                    "SCEP Client", "EnvelopedDataProcessor", "Failure in decrypting of CSR with the transaction id :"
                            + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName(),
                    "Confidential", ErrorSeverity.ERROR, "FAILURE");
            throw new PkiScepServiceException(ErrorMessages.FAIL_TO_DECRYPT);
        }

    }

    /**
     * It extracts issuer and subject name from RecipientIfo.
     *
     * @param RecipientInformation
     *            is RecipientInformation of EnvelopedData from which the IssuerAndSubjectName is decrypted.
     * @param caName
     *            is the alias name to read the content from the key store.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     */
    private void extractIssuerAndSubjectName(final RecipientInformation recipientInformation, final String caName,
                                             final Pkcs7ScepRequestData pkcs7ScepRequestData)
            throws PkiScepServiceException {
        try {
            final byte[] decryptedContent = decryptContent(recipientInformation, caName, true);
            pkcs7ScepRequestData.setIssuerAndSubjectName(IssuerAndSubjectName.getInstance(decryptedContent));
        } catch (PkiScepServiceException e) {
            logger.warn("Unable to extract Issuer and Subject Name in from GetCertInit Request with the transaction id :"
                    + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
            logger.debug("Unable to extract Issuer and Subject Name in from GetCertInit Request with the transaction id :"
                    + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName(), e);
            systemRecorder.recordSecurityEvent("SCEP Client", "EnvelopedDataProcessor",
                    "Failure in decrypting of IssuerAndSubject from GetCertInit Request with the transaction id :"
                            + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName(),
                    "Confidential", ErrorSeverity.WARNING, "FAILURE");

        } catch (final IOException e) {
            logger.error("Unable to extract Issuer and Subject Name in from GetCertInit Request with the transaction id :"
                    + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
            logger.debug("Unable to extract Issuer and Subject Name in from GetCertInit Request with the transaction id :"
                    + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName(), e);
            systemRecorder.recordError("PKI_RA_SCEP.FAIL_TO_READ_ISSUER_AND_SUBJECT_NAME", ErrorSeverity.ERROR, "EnvelopedDataProcessor",
                    "SCEP Enrollement for End Entity", "Unable to extract Issuer and Subject Name from GetCertInit Request with the transaction id :"
                            + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
            throw new PkiScepServiceException(ErrorMessages.FAIL_TO_READ_ISSUER_AND_SUBJECT_NAME);
        }
    }

    private void closeInputStream(final ASN1InputStream asn1InputStream, final Pkcs7ScepRequestData pkcs7ScepRequestData) {
        try {
            asn1InputStream.close();
        } catch (IOException e) {
            logger.error("Failed to process Envelope data in request with the transaction id :" + pkcs7ScepRequestData.getTransactionId()
                    + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
            systemRecorder.recordError("PKI_RA_SCEP.ENVELOPED_DATA_PROCESS_FAILED", ErrorSeverity.ERROR, "SCEP Client",
                    "SCEP Enrollement for End Entity", "Failed to process Envelope data in request with the transaction id :"
                            + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
            throw new PkiScepServiceException(ErrorMessages.REQUEST_PROCESS_FAILURE);
        }
    }
}