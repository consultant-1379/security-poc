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

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.*;
import org.junit.Assert;

import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.Constants;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.JUnitConstants;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepRequestData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.*;

/**
 * This class prepares Pkcs7ScepRequestData for the RequestMessage.
 */
public class Pkcs7ScepRequestSetUpData {

    private static Pkcs7ScepRequestData pkcs7ScepRequestData = null;

    public static Pkcs7ScepRequestData getPkcs7ScepRequest(final byte[] message) {

        CMSSignedData cmsSignedData = null;
        try {
            cmsSignedData = new CMSSignedData(message);

        } catch (final CMSException e) {

            Assert.fail(e.getMessage());
        }
        final SignedData signedData = SignedData.getInstance(cmsSignedData.toASN1Structure().getContent());
        pkcs7ScepRequestData = new Pkcs7ScepRequestData();
        extractCertificateData(signedData);
        extractSignerInformation(cmsSignedData);
        try {
            extractEnvelopedData(signedData, "lteipsecnecus", pkcs7ScepRequestData);
        } catch (final ProtocolException | IOException e) {
            Assert.fail(e.getMessage());
        }
        return pkcs7ScepRequestData;
    }

    /**
     * The method will extract the PKCS request data from the signed data
     * 
     * @param signedData
     *            is the singer data certificate holder
     */
    private static void extractCertificateData(final SignedData signedData) {

        final ASN1Set certificateSet = signedData.getCertificates();

        if (certificateSet != null && certificateSet.size() != 0) {
            final ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
            final DEROutputStream derOutPutStream = new DEROutputStream(byteOutputStream);
            try {
                derOutPutStream.writeObject(certificateSet.getObjectAt(0));
                final X509Certificate signerCertificate = CertificateUtility.getCertificateFromByteArray(byteOutputStream.toByteArray());
                pkcs7ScepRequestData.setSignerCertificate(signerCertificate);
                pkcs7ScepRequestData.setSubjectName(signerCertificate.getSubjectDN().getName());
                pkcs7ScepRequestData.setPublicKey(signerCertificate.getPublicKey());
                pkcs7ScepRequestData.setIssuerName(signerCertificate.getIssuerDN().getName());

            } catch (final IOException e) {
                Assert.fail(e.getMessage());
            }
        }

    }

    /**
     * This method will extract the signer attributes and validate the signer attributes
     * 
     * @param cmsSignedData
     *            is the holder for pkcs signature message holder
     */
    private static void extractSignerInformation(final CMSSignedData cmsSignedData) {

        SignerInformation signerInformation = null;
        final SignerInformationStore signerInformationStore = cmsSignedData.getSignerInfos();
        final Collection<?> signers = signerInformationStore.getSigners();
        final Iterator<?> it = signers.iterator();
        if (it.hasNext()) {
            signerInformation = (SignerInformation) it.next();

        }
        if (signerInformation != null) {
            pkcs7ScepRequestData.setSignerInformation(signerInformation);
            extractAuthenticateAttributes(signerInformation, pkcs7ScepRequestData);

            validateSignatureAlgorithm(signerInformation, pkcs7ScepRequestData);

        }

    }

    /**
     * This method will extract the attributes from the signer information
     * 
     * @param signerInformation
     *            is the signer information
     * @param pkcs7ScepRequestData2
     *            is the PKCS Request message
     */
    private static void extractAuthenticateAttributes(final SignerInformation signerInformation, final Pkcs7ScepRequestData pkcs7ScepRequestData2) {
        DERPrintableString attributeString = null;
        ASN1OctetString attributeASN1String = null;
        final HashMap<ASN1ObjectIdentifier, String> mapOfAuthAttributes = mapofAuthenticatedAttributes();

        final AttributeTable attributeTable = signerInformation.getSignedAttributes();
        final ASN1ObjectIdentifier[] attributeArray = mapOfAuthAttributes.keySet().toArray(new ASN1ObjectIdentifier[0]);

        for (final ASN1ObjectIdentifier asn1AtrributeOID : attributeArray) {

            final Attribute attribute = attributeTable.get(asn1AtrributeOID);
            if (attribute != null) {
                final ASN1Set values = attribute.getAttrValues();

                final Enumeration<?> enumeration = values.getObjects();

                if (asn1AtrributeOID.toString().equals(Constants.MESSAGE_TYPE_OID)) {
                    if (enumeration.hasMoreElements()) {
                        attributeString = (DERPrintableString) enumeration.nextElement();
                        pkcs7ScepRequestData.setMessageType(Integer.valueOf(attributeString.getString()));
                    }
                } else if (asn1AtrributeOID.toString().equals(Constants.SENDER_NONCE)) {
                    if (enumeration.hasMoreElements()) {
                        attributeASN1String = (ASN1OctetString) enumeration.nextElement();
                        pkcs7ScepRequestData.setSenderNonce(attributeASN1String.getOctets());
                    }
                } else if (asn1AtrributeOID.toString().equals(Constants.TRANSACTION_ID)) {
                    if (enumeration.hasMoreElements()) {
                        attributeString = (DERPrintableString) enumeration.nextElement();
                        pkcs7ScepRequestData.setTransactionId(attributeString.toString());
                    }
                }
            }

        }

    }

    /**
     * This method provides a map for the authentication attributes
     * 
     * @return mapOfAuthAttributes is the map containing the authenticated attributes
     */
    private static HashMap<ASN1ObjectIdentifier, String> mapofAuthenticatedAttributes() {

        final HashMap<ASN1ObjectIdentifier, String> mapOfAuthAttributes = new HashMap<ASN1ObjectIdentifier, String>();
        mapOfAuthAttributes.put(new ASN1ObjectIdentifier(Constants.MESSAGE_TYPE_OID), "Message Type");
        mapOfAuthAttributes.put(new ASN1ObjectIdentifier(Constants.SENDER_NONCE), "Sender Nonce ");
        mapOfAuthAttributes.put(new ASN1ObjectIdentifier(Constants.TRANSACTION_ID), "Transaction ID");
        mapOfAuthAttributes.put(CMSAttributes.messageDigest, "Message Digest ID");

        return mapOfAuthAttributes;

    }

    /**
     * This method will validates the signer information
     * 
     * @param signerInformation
     *            is the signer information data
     * @param pkcs7ScepRequestData
     *            is the PKCS request message
     */
    private static void validateSignatureAlgorithm(final SignerInformation signerInformation, final Pkcs7ScepRequestData pkcs7ScepRequestData) {
        try {
            final String DigestalgOid = signerInformation.getDigestAlgOID();
            final String EncryptAlgOid = signerInformation.getEncryptionAlgOID();
            pkcs7ScepRequestData.setContentDigestAlgOid(DigestalgOid);
            pkcs7ScepRequestData.setEncryptDigestAlgOID(EncryptAlgOid);
            setSignatureAlgorithm(pkcs7ScepRequestData);
        } catch (BadRequestException | SupportedAlgsNotFoundException e) {
            Assert.fail(e.getMessage());
        }
    }

    /**
     * This method will set the signature algorithm into the PKCS request message holder
     * 
     * @param pkcs7ScepRequestData
     *            is the PKCS request message
     */
    private static void setSignatureAlgorithm(final Pkcs7ScepRequestData pkcs7ScepRequestData) {
        final DefaultCMSSignatureAlgorithmNameGenerator cmsSignature = new DefaultCMSSignatureAlgorithmNameGenerator();
        pkcs7ScepRequestData.setSignatureAlgorithm(cmsSignature.getSignatureName(AlgorithmIdentifier.getInstance(pkcs7ScepRequestData.getContentDigestAlgOid()),
                AlgorithmIdentifier.getInstance(pkcs7ScepRequestData.getEncryptDigestAlgOid())));
    }

    /**
     * This method will extract the enveloped data from the signed data object
     * 
     * @param signedData
     *            is the signed data object
     * @param caName
     *            is the Certification Authority name
     * @param pkcs7ScepRequestData
     *            is the PKCs request message
     * @throws IOException
     *             is thrown when there is a failure in input/output operations
     */
    private static void extractEnvelopedData(final SignedData signedData, final String caName, final Pkcs7ScepRequestData pkcs7ScepRequestData) throws IOException {

        if (signedData.getEncapContentInfo().getContentType().equals(CMSObjectIdentifiers.data)) {
            final ASN1OctetString asn1OctetString = (ASN1OctetString) signedData.getEncapContentInfo().getContent();
            final ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(asn1OctetString.getOctets()));
            ASN1Sequence asn1Sequence = null;
            try {
                asn1Sequence = (ASN1Sequence) asn1InputStream.readObject();
                final ContentInfo contentInfo = ContentInfo.getInstance(asn1Sequence);
                if (contentInfo.getContentType().equals(CMSObjectIdentifiers.envelopedData)) {

                    final CMSEnvelopedData cmsEnvelopedData = new CMSEnvelopedData(contentInfo.getEncoded());
                    final RecipientInformationStore recipientInformationStore = cmsEnvelopedData.getRecipientInfos();
                    final Iterator<?> recipiterator = recipientInformationStore.getRecipients().iterator();
                    while (recipiterator.hasNext()) {
                        final RecipientInformation recipientInformation = (RecipientInformation) recipiterator.next();
                        pkcs7ScepRequestData.setRecipientInformation(recipientInformation);
                    }
                    pkcs7ScepRequestData.setContentEncryptionAlgOid(cmsEnvelopedData.getEncryptionAlgOID());
                }
            } catch (CMSException | IOException | ProtocolException e) {

                Assert.fail(e.getMessage());
            } finally {
                asn1InputStream.close();
            }
        }

    }

    /**
     * getPrivateKey method will fetch the private key from the key store
     * 
     * @param caName
     *            is the Certification Authority name
     * @param filePath
     *            is the key store file path
     * @param password
     *            is the key store file password
     * @return return the private key
     */
    public static PrivateKey getPrivateKey(final String caName, final String filePath, final String password) {
        PrivateKey privateKey = null;
        try {
            final KeyStore keyStore = KeyStore.getInstance(JUnitConstants.keyStoreType);
            final KeyStoreInfo keyStoreInfo = getKeyStoreInfo();
            keyStore.load(Pkcs7ScepRequestSetUpData.class.getResourceAsStream(keyStoreInfo.getFilePath()), keyStoreInfo.getPassword().toCharArray());
            privateKey = (PrivateKey) keyStore.getKey(caName, password.toCharArray());

        } catch (final KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | UnrecoverableKeyException e) {
            Assert.fail(e.getMessage());
        }
        return privateKey;
    }

    /**
     * getKeyStoreInfo will provide the key store information
     * 
     * @return returns the key store information
     */
    public static KeyStoreInfo getKeyStoreInfo() {

        final KeyStoreInfo keyStore = new KeyStoreInfo(JUnitConstants.filePath, KeyStoreType.valueOf(JUnitConstants.keyStoreType), JUnitConstants.password, JUnitConstants.caName);
        return keyStore;
    }

}
