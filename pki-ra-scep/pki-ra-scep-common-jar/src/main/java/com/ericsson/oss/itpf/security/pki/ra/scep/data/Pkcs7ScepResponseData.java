/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.scep.data;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;

/**
 * This class contains the data related to SCEP Response message. This data is be used to build build the response.
 *
 * @author xshaeru
 */
public class Pkcs7ScepResponseData {

    private CMSTypedData cmsTypedData;
    private boolean addSignerInfo;
    private List<Certificate> certificateList;
    private Hashtable<ASN1ObjectIdentifier, Attribute> attributes;
    private boolean encapsulate;
    private CMSSignedData cmsSignedData;
    private X509Certificate certificate;
    private X509Certificate recipientCert;
    private String contentEncryptionAlg;
    private X509Certificate signerCertificate;
    private PrivateKey signerPrivateKey;
    private byte[] encodedData;
    private String signatureAlgorithm;
    private String transactionId;

    /**
     * @return the cmsTypedData
     */
    public CMSTypedData getCmsTypedData() {
        return cmsTypedData;
    }

    /**
     * @param cmsTypedData
     *            the cmsTypedData to set
     */
    public void setCmsTypedData(final CMSTypedData cmsTypedData) {
        this.cmsTypedData = cmsTypedData;
    }

    /**
     * @return the addSignerInfo
     */
    public boolean isAddSignerInfo() {
        return addSignerInfo;
    }

    /**
     * @param addSignerInfo
     *            the addSignerInfo to set
     */
    public void setAddSignerInfo(final boolean addSignerInfo) {
        this.addSignerInfo = addSignerInfo;
    }

    /**
     * @return the certificateList
     */
    public List<Certificate> getCertificateList() {
        return certificateList;
    }

    /**
     * @param certificateList
     *            the certificateList to set
     */
    public void setCertificateList(final List<Certificate> certificateList) {
        this.certificateList = certificateList;
    }

    /**
     * @return the attributes
     */
    public Hashtable<ASN1ObjectIdentifier, Attribute> getAttributes() {
        return attributes;
    }

    /**
     * @param attributes
     *            the attributes to set
     */
    public void setAttributes(final Hashtable<ASN1ObjectIdentifier, Attribute> attributes) {
        this.attributes = attributes;
    }

    /**
     * @return the encapsulate
     */
    public boolean isEncapsulate() {
        return encapsulate;
    }

    /**
     * @param encapsulate
     *            the encapsulate to set
     */
    public void setEncapsulate(final boolean encapsulate) {
        this.encapsulate = encapsulate;
    }

    /**
     * @return the cmsSignedData
     */
    public CMSSignedData getCmsSignedData() {
        return cmsSignedData;
    }

    /**
     * @param cmsSignedData
     *            the cmsSignedData to set
     */
    public void setCmsSignedData(final CMSSignedData cmsSignedData) {
        this.cmsSignedData = cmsSignedData;
    }

    /**
     * @return the certificate
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * @param certificate
     *            the certificate to set
     */
    public void setCertificate(final X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * @return the recipientCert
     */
    public X509Certificate getRecipientCert() {
        return recipientCert;
    }

    /**
     * @param recipientCert
     *            the recipientCert to set
     */
    public void setRecipientCert(final X509Certificate recipientCert) {
        this.recipientCert = recipientCert;
    }

    /**
     * @return the contentEncryptionAlg
     */
    public String getContentEncryptionAlg() {
        return contentEncryptionAlg;
    }

    /**
     * @param contentEncryptionAlg
     *            the contentEncryptionAlg to set
     */
    public void setContentEncryptionAlg(final String contentEncryptionAlg) {
        this.contentEncryptionAlg = contentEncryptionAlg;
    }

    /**
     * @return the signerCertificate
     */
    public X509Certificate getSignerCertificate() {
        return signerCertificate;
    }

    /**
     * @param signerCertificate
     *            the signerCertificate to set
     */
    public void setSignerCertificate(final X509Certificate signerCertificate) {
        this.signerCertificate = signerCertificate;
    }

    /**
     * @return the signerPrivateKey
     */
    public PrivateKey getSignerPrivateKey() {
        return signerPrivateKey;
    }

    /**
     * @param signerPrivateKey
     *            the signerPrivateKey to set
     */
    public void setSignerPrivateKey(final PrivateKey signerPrivateKey) {
        this.signerPrivateKey = signerPrivateKey;
    }

    /**
     * @return the encodedData
     */
    public byte[] getEncodedData() {
        return encodedData;
    }

    /**
     * @param encodedData
     *            the encodedData to set
     */
    public void setEncodedData(final byte[] encodedData) {
        this.encodedData = encodedData;
    }

    /**
     * @return the signatureAlgorithm
     */
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * @param signatureAlgorithm
     *            the signatureAlgorithm to set
     */
    public void setSignatureAlgorithm(final String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * @return the transactionId
     */
    public String getTransactionId() {
        return transactionId;
    }

    /**
     * @param transactionId
     *            the transactionId to set
     */
    public void setTransactionId(final String transactionId) {
        this.transactionId = transactionId;
    }

}
