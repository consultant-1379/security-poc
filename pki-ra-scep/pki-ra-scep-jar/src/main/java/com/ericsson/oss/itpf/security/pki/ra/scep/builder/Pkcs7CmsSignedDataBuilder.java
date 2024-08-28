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
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Hashtable;

import javax.inject.Inject;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.scep.constants.ResponseStatus;
import com.ericsson.oss.itpf.security.pki.common.util.MessageDigestUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidAlgorithmException;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.Constants;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepResponseData;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.SignerInfoAttributeData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.PkiScepServiceException;

/**
 * This class contains generic methods which can be used for building the SCEP protocol related response messages. The response message is built with encapsulated data which contains signed data and
 * certificates, and with mandatory attributes. The Signature, contentEncryption and digest algorithms which we use during response building are fetched from request sent by SCEP client.
 *
 * @author xtelsow
 */
public abstract class Pkcs7CmsSignedDataBuilder {
    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method creates signed data to be sent in response.
     *
     * @param pkcs7ScepResponseData
     *            contains the data related to SCEP Response message. This data is be used to build build the response.
     * @return CMSSignedData CMSSignedData object contains the signer info or encapsulated cmsTypedData value.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     *
     */

    protected CMSSignedData buildSignedData(final Pkcs7ScepResponseData pkcs7ScepResponseData) throws PkiScepServiceException {
        logger.debug("createSignedData method of Pkcs7CmsSignedDataBuilder class");
        CMSSignedData cmsSigendData = null;
        try {

            final CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
            if (pkcs7ScepResponseData.getCertificateList() != null && !pkcs7ScepResponseData.getCertificateList().isEmpty()) {
                final JcaCertStore certs = new JcaCertStore(pkcs7ScepResponseData.getCertificateList());
                cmsSignedDataGenerator.addCertificates(certs);
            }
            if (pkcs7ScepResponseData.isAddSignerInfo()) {

                final ContentSigner contentSigner = new JcaContentSignerBuilder(pkcs7ScepResponseData.getSignatureAlgorithm()).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
                        pkcs7ScepResponseData.getSignerPrivateKey());

                final SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).setSignedAttributeGenerator(
                        new SimpleAttributeTableGenerator(new AttributeTable(pkcs7ScepResponseData.getAttributes()))).build(contentSigner, pkcs7ScepResponseData.getSignerCertificate());

                cmsSignedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);

            }

            cmsSigendData = cmsSignedDataGenerator.generate(pkcs7ScepResponseData.getCmsTypedData(), pkcs7ScepResponseData.isEncapsulate());

        } catch (final CMSException | CertificateEncodingException | OperatorCreationException e) {
            logger.error("Failed to generate signed data", e.getMessage());
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "Pkcs7SignedDataBuilder", "Failed to create Signed Data of the CertResponse for the request with transaction id "
                    + pkcs7ScepResponseData.getTransactionId(), "SCEP Response Build", ErrorSeverity.ERROR, "FAILURE");

            throw new PkiScepServiceException(ErrorMessages.RESPONSE_BUILD_FAILURE);

        }
        logger.debug("End  of createSignedData method of Pkcs7CmsSignedDataBuilder class");

        return cmsSigendData;

    }

    /**
     * This method creates enveloped data with CMSSignedData data and certificate or recipient certificate.
     * 
     * @param pkcs7ScepResponseData
     *            contains the data related to SCEP Response message. This data is be used to build build the response.
     * @return CMSTypedData CMSTypedData object contains the signed data,certificate or recipient certificate values.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     */
    protected CMSTypedData buildEnvelopedData(final Pkcs7ScepResponseData pkcs7ScepResponseData) throws PkiScepServiceException {

        logger.debug("createEnvelopedData method of ResponseBuilder class");

        final CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
        CMSTypedData cmsTypedData = null;
        try {

            if (pkcs7ScepResponseData.getRecipientCert() == null) {
                cmsEnvelopedDataGenerator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(pkcs7ScepResponseData.getCertificate()));

            } else {
                cmsEnvelopedDataGenerator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(pkcs7ScepResponseData.getRecipientCert()));

            }

            CMSEnvelopedData cmsEnvelopedData;
            cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(new CMSProcessableByteArray(pkcs7ScepResponseData.getCmsSignedData().getEncoded()), new JceCMSContentEncryptorBuilder(
                    new ASN1ObjectIdentifier(pkcs7ScepResponseData.getContentEncryptionAlg())).build());
            pkcs7ScepResponseData.setEncodedData(cmsEnvelopedData.getEncoded());
            cmsTypedData = new CMSProcessableByteArray(pkcs7ScepResponseData.getEncodedData());
        } catch (final CertificateException | IOException | CMSException e) {
            logger.error("Failed to create Enveloped Data in the CertResponse for the request with transaction id " + pkcs7ScepResponseData.getTransactionId(), e.getMessage());
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "Pkcs7SignedDataBuilder", "Failed to create Enveloped Data of the CertResponse for the request with transaction id "
                    + pkcs7ScepResponseData.getTransactionId(), "SCEP Response Build", ErrorSeverity.ERROR, "FAILURE");

            throw new PkiScepServiceException(ErrorMessages.RESPONSE_BUILD_FAILURE);

        }

        logger.debug("End of createEnvelopedData method of Pkcs7CmsSignedDataBuilder class");

        return cmsTypedData;

    }

    /**
     * This method creates hash table with authenticated attributes like status, transactionId, senderNonce,failInfo and recipientNonce and remaining optional attributes according to scenario and
     * encapsulates in response message.
     * 
     * @param attributes
     *            is the attributes which will be present in SingerInfo of CertResp Message.
     * @param pkcs7ScepResponseData
     *            contains the data related to SCEP Response message. This data is be used to build build the response.
     * 
     * @return attributes table which contains the list of attributes to be sent in response to SCEP client.
     *
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     */
    protected Hashtable<ASN1ObjectIdentifier, Attribute> getAuthenticatedAttributes(final SignerInfoAttributeData signerInfoAttributes, final Pkcs7ScepResponseData pkcs7ScepResponseData)
            throws PkiScepServiceException {

        logger.debug(" getAuthenticatedAttributes method in Pkcs7CmsSignedDataBuilder class ");

        final Hashtable<ASN1ObjectIdentifier, Attribute> attributes = new Hashtable<>();
        final SecureRandom randomSource = new SecureRandom();
        final byte[] senderNonce = new byte[16];
        randomSource.nextBytes(senderNonce);

        addAttribute(attributes, Constants.TRANSACTION_ID, new DERPrintableString(signerInfoAttributes.getTransactionId()));
        addAttribute(attributes, Constants.RECEPIENT_NONCE, new DEROctetString(signerInfoAttributes.getRecipientNonce()));
        addAttribute(attributes, Constants.SENDER_NONCE, new DEROctetString(senderNonce));
        addAttribute(attributes, Constants.STATUS_OID, new DERPrintableString(Integer.toString(signerInfoAttributes.getStatus().getStatus())));
        addAttribute(attributes, PKCSObjectIdentifiers.pkcs_9_at_contentType.getId(), PKCSObjectIdentifiers.data);
        addAttribute(attributes, Constants.MESSAGE_TYPE_OID, new DERPrintableString(Integer.toString(3)));

        if (signerInfoAttributes.getFailInfo() != null) {
            addAttribute(attributes, Constants.FAIL_INFO_OID, new DERPrintableString(Integer.toString(signerInfoAttributes.getFailInfo().getScepFailInfo())));
        }
        byte[] digest = null;
        if (ResponseStatus.SUCCESS == signerInfoAttributes.getStatus()) {

            try {
                digest = MessageDigestUtility.generateMessageDigest(signerInfoAttributes.getDigestAlgorithm(), pkcs7ScepResponseData.getEncodedData());
            } catch (final InvalidAlgorithmException e) {
                logger.error("Failed to create Message Digest for CertResponse message  for the request with transaction id " + signerInfoAttributes.getTransactionId(), e.getMessage());
                systemRecorder.recordError(
                        "PKI_RA_SCEP.CERT_RESPONSE_BUILDER",
                        ErrorSeverity.ERROR,
                        "PKIRASCEPService",
                        "SCEP Enrollment for End Entity",
                        "Failed to create message digest of authenticated attributes to prepare CertResponse with success status for the request with transaction id "
                                + signerInfoAttributes.getTransactionId());
                throw new PkiScepServiceException(ErrorMessages.SUCCESS_RESP_FAILURE);
            }

        } else {
            try {
                digest = MessageDigestUtility.generateMessageDigest(signerInfoAttributes.getDigestAlgorithm(), new byte[0]);
            } catch (final InvalidAlgorithmException e) {
                logger.error("Failed to create Message Digest for CertResponse message for the request with transaction id " + signerInfoAttributes.getTransactionId(), e.getMessage());
                systemRecorder.recordError(
                        "PKI_RA_SCEP.CERT_RESPONSE_BUILDER",
                        ErrorSeverity.ERROR,
                        "PKIRASCEPService",
                        "SCEP Enrollment for End Entity",
                        "Failed to create message digest of authenticated attributes to prepare CertResponse with pending/failure status for the request with transaction id "
                                + signerInfoAttributes.getTransactionId());
                throw new PkiScepServiceException(ErrorMessages.CERT_RESP_FAILURE);
            }
        }
        addAttribute(attributes, CMSAttributes.messageDigest.getId(), new DEROctetString(digest));
        logger.debug("End of getAuthenticatedAttributes method in Pkcs7CmsSignedDataBuilder class ");
        return attributes;
    }

    /**
     * 
     * This method adds authenticated attributes(status, transactionId, senderNonce,failInfo and recipientNonce and remaining optional attributes according to scenario) to the hash Table. The
     * identifier and value are converted to ANS1 format and are added to attribute. Hence the hash table contains the ASN1ObjectIdentifier as key and ASN1Encodable object as value.
     * 
     * @param attributes
     *            the hash table to which the authenticated attributes have to be added.
     * @param identifier
     *            the attribute identifier (ex:TRANSACTION_ID,RECEPIENT_NONCE etc).
     * @param value
     *            value of the attribute.
     */
    private void addAttribute(final Hashtable<ASN1ObjectIdentifier, Attribute> attributes, final String identifier, final ASN1Encodable value) {
        logger.debug(" addAttribute method in Pkcs7CmsSignedDataBuilder class");
        final ASN1ObjectIdentifier asn1Identifier = new ASN1ObjectIdentifier(identifier);
        final ASN1Set asn1Set = new DERSet(value);
        final Attribute attribute = new Attribute(asn1Identifier, asn1Set);
        attributes.put(attribute.getAttrType(), attribute);
        logger.debug(" End of addAttribute method in Pkcs7CmsSignedDataBuilder class");

    }
}
