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
package com.ericsson.oss.itpf.security.pki.ra.scep.data;

import java.io.Serializable;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformation;

/**
 * This class contains the data related to SCEP Request message. This data is be used to process the request and to build the response.
 *
 * @author xshaeru
 */
public class Pkcs7ScepRequestData implements Serializable {

    private static final long serialVersionUID = 1L;
    private final EnvelopedData envelopedData;
    private final SignerInformationData signerInformationData;
    private final CertificateData certificateData;

    /**
     * This constructor sets values to the instance variables.
     */
    public Pkcs7ScepRequestData() {

        certificateData = new CertificateData();
        envelopedData = new EnvelopedData();
        signerInformationData = new SignerInformationData();

    }

    /**
     * This is the inner class which contains the data related to the certificates sent by the SCEP client.
     *
     */
    private final class CertificateData {

        private PublicKey publicKey;

        private PublicKey selfSignedCertPublicKey;

        private String subjectName;

        private String endEntityName;

        private X509Certificate signerCertificate;

    }

    /**
     *
     * This inner class contains the signerInformation data which will be extracted from SignerInformation of SigneData.
     *
     */
    private final class SignerInformationData {

        private int messageType;

        private byte[] senderNonce;

        private String transactionId;

        private String contentDigestAlgOid;

        private String encryptDigestAlgOid;

        private SignerInformation signerInformation;

        private String signatureAlgorithm;

    }

    /**
     * 
     * This inner class contains the fields of EnvelopedData of which are extracted from the EnvelopedData of Pkcs7ScepRequest.
     *
     */

    public class EnvelopedData {

        private RecipientInformation recipientInformation;

        private IssuerAndSubjectName issuerAndSubjectName;

        private String issuerName;

        private byte[] pkcsReqinfo;

        private String contentEncryptionAlgOid;
    }

    /**
     * @return the messageType.
     */
    public int getMessageType() {
        return signerInformationData.messageType;
    }

    /**
     * @param messageType
     *            the messageType to set.
     */
    public void setMessageType(final int messageType) {
        signerInformationData.messageType = messageType;
    }

    /**
     * @return the senderNonce.
     */
    public byte[] getSenderNonce() {
        return signerInformationData.senderNonce;
    }

    /**
     * @param senderNonce
     *            the senderNonce to set.
     */
    public void setSenderNonce(final byte[] senderNonce) {
        signerInformationData.senderNonce = senderNonce;
    }

    /**
     * @return the transactionId.
     */
    public String getTransactionId() {
        return signerInformationData.transactionId;
    }

    /**
     * @param transactionId
     *            the transactionId to set.
     */
    public void setTransactionId(final String transactionId) {
        signerInformationData.transactionId = transactionId;
    }

    /**
     * @return the contentDigestAlgOID.
     */
    public String getContentDigestAlgOid() {
        return signerInformationData.contentDigestAlgOid;
    }

    /**
     * @param contentDigestAlgOid
     *            the contentDigestAlgOID to set.
     */
    public void setContentDigestAlgOid(final String contentDigestAlgOid) {
        signerInformationData.contentDigestAlgOid = contentDigestAlgOid;
    }

    /**
     * @return the encryptDigestAlgOID.
     */
    public String getEncryptDigestAlgOid() {
        return signerInformationData.encryptDigestAlgOid;
    }

    /**
     * @param encryptDigestAlgOid
     *            the encryptDigestAlgOID to set.
     */
    public void setEncryptDigestAlgOID(final String encryptDigestAlgOid) {
        signerInformationData.encryptDigestAlgOid = encryptDigestAlgOid;
    }

    /**
     * @return the recipientInformation.
     */
    public RecipientInformation getRecipientInformation() {
        return envelopedData.recipientInformation;
    }

    /**
     * @param recipientInformation
     *            the recipientInformation to set.
     */
    public void setRecipientInformation(final RecipientInformation recipientInformation) {
        envelopedData.recipientInformation = recipientInformation;
    }

    /**
     * @return the issuerAndSubjectName.
     */
    public IssuerAndSubjectName getIssuerAndSubjectName() {
        return envelopedData.issuerAndSubjectName;
    }

    /**
     * @param issuerAndSubjectName
     *            the issuerAndSubjectName to set.
     */
    public void setIssuerAndSubjectName(final IssuerAndSubjectName issuerAndSubjectName) {
        envelopedData.issuerAndSubjectName = issuerAndSubjectName;
    }

    /**
     * @return the issuerName.
     */
    public String getIssuerName() {
        return envelopedData.issuerName;
    }

    /**
     * @param issuerName
     *            the issuerName to set.
     */
    public void setIssuerName(final String issuerName) {
        envelopedData.issuerName = issuerName;
    }

    /**
     * @return the pkcsReqinfo.
     */
    public byte[] getPkcsReqinfo() {
        return envelopedData.pkcsReqinfo;
    }

    /**
     * @param pkcsReqinfo
     *            the pkcsReqinfo to set.
     */
    public void setPkcsReqinfo(final byte[] pkcsReqinfo) {
        envelopedData.pkcsReqinfo = pkcsReqinfo;
    }

    /**
     * @return the contentEncryptionAlg.
     */
    public String getContentEncryptionAlgOid() {
        return envelopedData.contentEncryptionAlgOid;
    }

    /**
     * @param contentEncryptionAlg
     *            the contentEncryptionAlg to set.
     */
    public void setContentEncryptionAlgOid(final String contentEncryptionAlgOid) {
        envelopedData.contentEncryptionAlgOid = contentEncryptionAlgOid;
    }

    /**
     * @return the publicKey.
     */
    public PublicKey getPublicKey() {
        return certificateData.publicKey;
    }

    /**
     * @param publicKey
     *            the publicKey to set.
     */
    public void setPublicKey(final PublicKey publicKey) {
        certificateData.publicKey = publicKey;
    }

    /**
     * @return the selfSignedCertPublicKey.
     */
    public PublicKey getSelfSignedCertPublicKey() {
        return certificateData.selfSignedCertPublicKey;
    }

    /**
     * @param selfSignedCertPublicKey
     *            the selfSignedCertPublicKey to set.
     */
    public void setSelfSignedCertPublicKey(final PublicKey selfSignedCertPublicKey) {
        certificateData.selfSignedCertPublicKey = selfSignedCertPublicKey;
    }

    /**
     * @return the subjectName.
     */
    public String getSubjectName() {
        return certificateData.subjectName;
    }

    /**
     * @param subjectName
     *            the subjectName to set.
     */
    public void setSubjectName(final String subjectName) {
        certificateData.subjectName = subjectName;
    }

    /**
     * @return the endEntityName.
     */
    public String getEndEntityName() {
        return certificateData.endEntityName;
    }

    /**
     * @param endEntityName
     *            the endEntityName to set.
     */
    public void setEndEntityName(final String endEntityName) {
        certificateData.endEntityName = endEntityName;
    }

    /**
     * @return the signerCertificate.
     */
    public X509Certificate getSignerCertificate() {
        return certificateData.signerCertificate;
    }

    /**
     * @param signerCertificate
     *            the signerCertificate to set.
     */
    public void setSignerCertificate(final X509Certificate signerCertificate) {
        certificateData.signerCertificate = signerCertificate;
    }

    /**
     * @return the signerInformation.
     */
    public SignerInformation getSignerInformation() {
        return signerInformationData.signerInformation;
    }

    /**
     * @param signerInformation
     *            the signerInformation to set.
     */
    public void setSignerInformation(final SignerInformation signerInformation) {
        signerInformationData.signerInformation = signerInformation;
    }

    /**
     * @return the signatureAlgorithm.
     */
    public String getSignatureAlgorithm() {
        return signerInformationData.signatureAlgorithm;
    }

    /**
     * @param signatureAlgorithm
     *            the signatureAlgorithm to set.
     */
    public void setSignatureAlgorithm(final String signatureAlgorithm) {
        signerInformationData.signatureAlgorithm = signatureAlgorithm;
    }

}
