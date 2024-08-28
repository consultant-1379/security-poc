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
package com.ericsson.oss.itpf.security.pki.ra.scep.builder;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;

import javax.inject.Inject;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.cms.*;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.scep.constants.ResponseStatus;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateConversionException;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.FailureInfo;
import com.ericsson.oss.itpf.security.pki.ra.scep.cryptoservice.CryptoService;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.*;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.BadRequestException;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.PkiScepServiceException;

/**
 * CertResponseBuilder Program builds the response for PKCS and GetCertInitial requests.The response is built with valid certificate,signed data,mandatory attributes, and status information in success
 * scenarios. If there is any error while processing the request, the corresponding error information is captured in this response. This response contains the message in DER encodable format which can
 * be understood by SCEP client.
 *
 * @author xtelsow
 */
public class CertResponseBuilder extends Pkcs7CmsSignedDataBuilder {
    @Inject
    private Logger logger;

    @Inject
    private Pkcs7ScepRequestData pkcs7ScepRequestData;

    @Inject
    private CryptoService cryptoService;

    @Inject
    private Pkcs7ScepResponseData pkcs7ScepResponseData;

    @Inject
    private SignerInfoAttributeData signerInfoAttributes;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method is used to set the values of instance variables which are used in building the response message.
     *
     * @param pkcs7ScepRequestData
     *            has the fields which are used for building the message.
     * @param caName
     *            is the alias name to get the content from the key Store.
     *
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     * @throws BadRequestException
     *             is thrown when exception occurs while getting certificate from keystore.
     */

    public void populateResponseData(final Pkcs7ScepRequestData pkcs7ScepRequestData, final String caName, final Pkcs7ScepResponseData pkcs7ResponseData) throws PkiScepServiceException,
            BadRequestException {
        pkcs7ResponseData.setRecipientCert(pkcs7ScepRequestData.getSignerCertificate());
        pkcs7ResponseData.setSignerCertificate((X509Certificate) cryptoService.readCertificate(caName, false));
        this.pkcs7ScepRequestData = pkcs7ScepRequestData;
        pkcs7ResponseData.setSignatureAlgorithm(pkcs7ScepRequestData.getSignatureAlgorithm());
        pkcs7ResponseData.setSignerPrivateKey(cryptoService.readPrivateKey(caName));
        this.pkcs7ScepResponseData = pkcs7ResponseData;
    }

    /**
     * This method is used to build the certResponse with Pending message. The internal methods of this method are inherited from the Super class Pkcs7CmsSignedDataBuilder.
     * 
     * @return byte[] which contains pkcs7message
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     */

    public byte[] buildPendingCertResponse() throws PkiScepServiceException {
        logger.debug("createPendingCertResponse method in CertResponseBuilder class");
        byte[] response = null;

        signerInfoAttributes.setDigestAlgorithm(pkcs7ScepRequestData.getContentDigestAlgOid());
        signerInfoAttributes.setFailInfo(null);
        signerInfoAttributes.setRecipientNonce(pkcs7ScepRequestData.getSenderNonce());
        signerInfoAttributes.setStatus(ResponseStatus.PENDING);
        signerInfoAttributes.setTransactionId(pkcs7ScepRequestData.getTransactionId());

        final Hashtable<ASN1ObjectIdentifier, Attribute> attributes = getAuthenticatedAttributes(signerInfoAttributes, pkcs7ScepResponseData);
        try {
            pkcs7ScepResponseData.setCmsTypedData(new CMSProcessableByteArray(new byte[0]));
            pkcs7ScepResponseData.setAddSignerInfo(true);
            pkcs7ScepResponseData.setCertificateList(null);
            pkcs7ScepResponseData.setAttributes(attributes);
            pkcs7ScepResponseData.setEncapsulate(true);
            pkcs7ScepResponseData.setTransactionId(pkcs7ScepRequestData.getTransactionId());
            final CMSSignedData cmsSignedData = buildSignedData(pkcs7ScepResponseData);
            response = cmsSignedData.getEncoded();
        } catch (final IOException e) {
            logger.error("Caught IOException while building certResponse: " + e.getMessage());
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "CertResponseBuilder", "Unable to send response to End Entity for the Certificate Request with the transaction id :"
                    + pkcs7ScepRequestData.getTransactionId(), "CertificateResponse", ErrorSeverity.ERROR, "FAILURE");
            throw new PkiScepServiceException(ErrorMessages.PENDING_RESP_FAILURE);
        }
        logger.debug("End of createPendingCertResponse method in CertResponseBuilder class");
        return response;
    }

    /**
     * This method is used to build the certResponse with failure message. The internal methods of this method are inherited from the Super class Pkcs7CmsSignedDataBuilder
     * 
     * @param failInfo
     *            is the failure information to be added to failure info field of pkcs7message signed data.
     * @return byte[] which contains pkcs7message
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     */

    public byte[] buildFailureCertResponse(final FailureInfo failureInfo) throws PkiScepServiceException {
        logger.debug("createFailureCertResponse method in CertResponseBuilder class");
        byte[] response;
        signerInfoAttributes.setDigestAlgorithm(pkcs7ScepRequestData.getContentDigestAlgOid());
        signerInfoAttributes.setFailInfo(failureInfo);
        signerInfoAttributes.setRecipientNonce(pkcs7ScepRequestData.getSenderNonce());
        signerInfoAttributes.setStatus(ResponseStatus.FAILURE);
        signerInfoAttributes.setTransactionId(pkcs7ScepRequestData.getTransactionId());

        final Hashtable<ASN1ObjectIdentifier, Attribute> attributes = getAuthenticatedAttributes(signerInfoAttributes, pkcs7ScepResponseData);
        try {
            pkcs7ScepResponseData.setCmsTypedData(new CMSProcessableByteArray(new byte[0]));
            pkcs7ScepResponseData.setAddSignerInfo(true);
            pkcs7ScepResponseData.setCertificateList(null);
            pkcs7ScepResponseData.setAttributes(attributes);
            pkcs7ScepResponseData.setEncapsulate(true);
            pkcs7ScepResponseData.setTransactionId(pkcs7ScepRequestData.getTransactionId());
            final CMSSignedData cmsSignedData = buildSignedData(pkcs7ScepResponseData);
            response = cmsSignedData.getEncoded();
        } catch (final IOException e) {
            logger.error("Caught IOException while building certResponse: {}" , e.getMessage());
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "CertResponseBuilder", "Failed to create CertResponse with failure status for the request with the transaction id : "
                    + pkcs7ScepRequestData.getTransactionId(), "CertificateResponse", ErrorSeverity.ERROR, "FAILURE");
            throw new PkiScepServiceException(ErrorMessages.FAILURE_RESP_FAILURE);
        }
        logger.debug("End of createFailureCertResponse method in CertResponseBuilder class");
        return response;
    }

    /**
     * This method is used to build the certResponse with Success message. The internal methods of this method are inherited from the Super class Pkcs7CmsSignedDataBuilder
     * 
     * @param clientCertificate
     *            is the client requested Certificate.
     * @return byte[] which contains pkcs7message
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response. message which is SCEP CertRep message.
     */
    public byte[] buildSuccessCertResponse(final byte[] clientCertificate) throws PkiScepServiceException {
        logger.debug("createSuccessCertResponse method in CertResponseBuilder class");
        byte[] response;
        final ArrayList<Certificate> certificateList = new ArrayList<>();
        X509Certificate certificate = null;
        if (clientCertificate == null) {
            logger.error("Unable to provide the requested certificate");
            systemRecorder.recordError("PKI_RA_SCEP.CERTIFICATE_NOT_PROVIDED", ErrorSeverity.ERROR, "PKIRASCEPService", "SCEP Enrollment for End Entity",
                    "Unable to provide the certificate for End Entity for the certificate request with the transaction id :" + pkcs7ScepRequestData.getTransactionId());
            throw new PkiScepServiceException(ErrorMessages.FAIL_TO_PROVIDE_CERTIFICATE);
        } else {
            try {
                certificate = CertificateUtility.getCertificateFromByteArray(clientCertificate);
            } catch (CertificateConversionException e) {
                logger.error("Fail to convert certificate {}", e.getMessage());
                throw new PkiScepServiceException(ErrorMessages.REQUEST_PROCESS_FAILURE);
            }
            certificateList.add(certificate);
        }
        try {
            pkcs7ScepResponseData.setCmsTypedData(new CMSAbsentContent());
            pkcs7ScepResponseData.setAddSignerInfo(false);
            pkcs7ScepResponseData.setCertificateList(certificateList);
            pkcs7ScepResponseData.setAttributes(null);
            pkcs7ScepResponseData.setEncapsulate(false);
            pkcs7ScepResponseData.setTransactionId(pkcs7ScepRequestData.getTransactionId());
            CMSSignedData cmsSignedData = buildSignedData(pkcs7ScepResponseData);

            pkcs7ScepResponseData.setCmsSignedData(cmsSignedData);
            pkcs7ScepResponseData.setCertificate(certificate);
            pkcs7ScepResponseData.setContentEncryptionAlg(pkcs7ScepRequestData.getContentEncryptionAlgOid());

            final CMSTypedData cmsTypedData = buildEnvelopedData(pkcs7ScepResponseData);
            signerInfoAttributes.setDigestAlgorithm(pkcs7ScepRequestData.getContentDigestAlgOid());
            signerInfoAttributes.setFailInfo(null);
            signerInfoAttributes.setRecipientNonce(pkcs7ScepRequestData.getSenderNonce());
            signerInfoAttributes.setStatus(ResponseStatus.SUCCESS);
            signerInfoAttributes.setTransactionId(pkcs7ScepRequestData.getTransactionId());

            final Hashtable<ASN1ObjectIdentifier, Attribute> attributes = getAuthenticatedAttributes(signerInfoAttributes, pkcs7ScepResponseData);
            pkcs7ScepResponseData.setCmsTypedData(cmsTypedData);
            pkcs7ScepResponseData.setAddSignerInfo(true);
            pkcs7ScepResponseData.setCertificateList(null);
            pkcs7ScepResponseData.setAttributes(attributes);
            pkcs7ScepResponseData.setEncapsulate(true);
            cmsSignedData = buildSignedData(pkcs7ScepResponseData);
            response = cmsSignedData.getEncoded();
        } catch (final IOException e) {
            logger.error("Caught IOException while building certResponse : {}" , e.getMessage());
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "CertResponseBuilder", "Failed to create CertResponse with success status for the request with the transaction id :"
                    + pkcs7ScepRequestData.getTransactionId(), "CertificateResponse", ErrorSeverity.ERROR, "FAILURE");
            throw new PkiScepServiceException(ErrorMessages.SUCCESS_RESP_FAILURE);
        }
        logger.debug("End of createSuccessCertResponse method in CertResponseBuilder class");
        return response;
    }

}
