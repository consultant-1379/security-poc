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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.inject.Inject;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.FailureInfo;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepRequestData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.*;
import com.ericsson.oss.itpf.security.pki.ra.scep.validator.AlgorithmValidator;
import com.ericsson.oss.itpf.security.pki.ra.scep.validator.SignatureValidator;

/**
 * This class processes PKCSReq message and getCertInitial messages.
 *
 * @author xtelsow
 */
public class PkiOperationReqProcessor {

    @Inject
    private Logger logger;

    @Inject
    private SignatureValidator signatureValidator;

    @Inject
    private AlgorithmValidator algorithmValidator;

    @Inject
    private EnvelopedDataProcessor envDataProcessor;

    @Inject
    private SignerInfoProcessor signerInfoProcessor;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method is used to process the SCEP PKCS7 CMS message. It will call all the methods which are for extracting and validating request message fields and sets the required fields of
     * pkcs7ScepRequestData and return it for Preparing response.
     * 
     * @param message
     *            the byte[] message which is to be converted to CMSSignedData object.
     * @param caName
     *            is the alias name to read the content from the key store.
     * @param pkcs7ScepRequestData
     *            contains all the info from request messages which are required to build the response.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     * @throws BadRequestException
     *             is thrown when exception occurs while extracting the certificate data.
     */

    public void processRequest(final byte[] message, final String caName, final Pkcs7ScepRequestData pkcs7ScepRequestData) throws PkiScepServiceException, BadRequestException {

        logger.debug("processRequest method of PkiOperationReqProcessor");
        CMSSignedData cmsSignedData = null;
        try {
            cmsSignedData = new CMSSignedData(message);

            final SignedData signedData = SignedData.getInstance(cmsSignedData.toASN1Structure().getContent());

            if (signedData == null) {
                logger.error("Signed data is not present");
                systemRecorder.recordError("PKI_RA_SCEP.SIGNED_DATA_EMPTY", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollment for End Entity",
                        "Signed data is not present in PKCS7 Request with the transaction Id :" + pkcs7ScepRequestData.getTransactionId());
                throw new PkiScepServiceException(ErrorMessages.SIGNED_DATA_NOT_FOUND);
            }
            extractCertificateData(signedData, pkcs7ScepRequestData);
            signerInfoProcessor.extractSignerInformation(cmsSignedData, pkcs7ScepRequestData);
            algorithmValidator.validateSignatureAlgorithm(pkcs7ScepRequestData);
            algorithmValidator.validateSignedDataDigestAlg(signedData);
            envDataProcessor.extractEnvelopedData(signedData, caName, pkcs7ScepRequestData);
            if (!((signatureValidator.validateSignature(pkcs7ScepRequestData.getSignerInformation(), pkcs7ScepRequestData.getPublicKey())) || (signatureValidator.validateSignature(
                    pkcs7ScepRequestData.getSignerInformation(), pkcs7ScepRequestData.getSelfSignedCertPublicKey())))) {
                logger.error("Signature verification failed for the request with the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                        + pkcs7ScepRequestData.getEndEntityName());
                systemRecorder.recordSecurityEvent(
                        "SCEP Client",
                        "PKIOperationReqProcessor",
                        "Signature verification failed for the request with the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                                + pkcs7ScepRequestData.getEndEntityName(), "Integrity", ErrorSeverity.ERROR, "FAILURE");
                throw new BadMessageCheckException(FailureInfo.BADMESSAGECHECK.name());
            }

            logger.debug("End of processRequest method of PkiOperationReqProcessor");

        } catch (final CMSException e) {
            logger.error("CMSException due to malformed content or IOException reading content from the request");
            systemRecorder.recordError("PKI_RA_SCEP.MALFORMED_CONTENT", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollment for End Entity",
                    "Malformed content or error occured while reading the content from PKCS7 Request");
            throw new InvalidRequestMessageException(ErrorMessages.INVALID_REQUEST_MESSAGE);
        } catch (final UnSupportedAlgException e) {
            logger.error("Unsupported algorithm in the request message");
            throw new UnSupportedAlgException(FailureInfo.BADALG.name());
        } catch (final UnSupportedMsgTypeException e) {
            logger.error("Unsupported message type in the request message in PKCS7 Request with the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                    + pkcs7ScepRequestData.getEndEntityName());
            systemRecorder.recordError("PKI_RA_SCEP.UNSUPPORTED_MESSAGE", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollment for End Entity",
                    "Unsupported message type in the request message in PKCS7 Request with the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                            + pkcs7ScepRequestData.getEndEntityName());
            throw new UnSupportedMsgTypeException(FailureInfo.BADREQUEST.name());
        } catch (final SupportedAlgsNotFoundException e) {
            logger.error("No algorithms found in cache");
            throw new PkiScepServiceException(ErrorMessages.REQUEST_PROCESS_FAILURE);
        }
    }

    /**
     * This method extracts the certificate and required certificate fields, sets the values to CertificatData fields of pkcs7ScepRequestData.
     * 
     * @param signedData
     *            is the ASN1 SingedData of PKCSReq message.
     * @param pkcs7ScepRequestData
     *            contains all the info from request messages which are required to build the response.
     * @throws BadRequestException
     *             is thrown when Signer Certificate is not found in SignedData.
     */
    private void extractCertificateData(final SignedData signedData, final Pkcs7ScepRequestData pkcs7ScepRequestData) throws BadRequestException {
        logger.debug("extractCertificateData method of PkiOperationReqProcessor");
        final ASN1Set certificateSet = signedData.getCertificates();

        if (certificateSet != null && certificateSet.size() != 0) {
            final ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
            final DEROutputStream derOutPutStream = new DEROutputStream(byteOutputStream);
            try {
                derOutPutStream.writeObject(certificateSet.getObjectAt(0));
                final X509Certificate signerCertificate = CertificateUtility.getCertificateFromByteArray(byteOutputStream.toByteArray());
                pkcs7ScepRequestData.setSignerCertificate(signerCertificate);
                pkcs7ScepRequestData.setSubjectName(signerCertificate.getSubjectDN().getName());
                pkcs7ScepRequestData.setEndEntityName(getCommonName(signerCertificate));
                pkcs7ScepRequestData.setSelfSignedCertPublicKey(signerCertificate.getPublicKey());

            } catch (final IOException | CertificateEncodingException e) {
                logger.error("CaughtException while getting X509 Certificate" + e.getMessage());
                systemRecorder.recordError("PKI_RA_SCEP.CERTIFICATE_READ_FAILURE", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollment for End Entity",
                        "Failure in reading X509 Certificate from the Request with the Transaction Id :" + pkcs7ScepRequestData.getTransactionId());

                throw new BadRequestException(ErrorMessages.SIGNER_CERTIFICATE_NOT_FOUND);
            }
        } else {
            logger.error("Signer Certifcate not found in SignedData");
            systemRecorder.recordError("PKI_RA_SCEP.SIGNER_CERTIFICATE_NOT_FOUND", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollment for End Entity",
                    "Signer Certifcate not found in SignedData in PKCS7 Request with the Transaction Id :" + pkcs7ScepRequestData.getTransactionId());
            throw new BadRequestException(ErrorMessages.SIGNER_CERTIFICATE_NOT_FOUND);
        }
        logger.debug("End of extractCertificateData method of PkiOperationReqProcessor");

    }

    private String getCommonName(final X509Certificate certificate) throws CertificateEncodingException {
        final X500Name x500Name = new JcaX509CertificateHolder(certificate).getSubject();
        final RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
        return cn.getFirst().getValue().toString();
    }

}
