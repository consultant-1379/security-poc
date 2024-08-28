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
package com.ericsson.oss.itpf.security.pki.manager.test.setup;

import javax.xml.datatype.Duration;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtensions;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;

/**
 * This class acts as builder for {@link CertificateGenerationInfoSetUpData}
 */
public class CertificateGenerationInfoSetUpData {

    private CertificateVersion version;
    private Duration validity;
    private boolean subjectUniqueIdentifier;
    private boolean issuerUniqueIdentifier;
    private Duration skewCertificateTime;
    private Algorithm keyGenerationAlgorithm;
    private Algorithm signatureAlgorithm;
    private Algorithm issuerSignatureAlgorithm;
    private CertificateExtensions certificateExtensions;
    private CertificateRequest certificateRequest;
    private CertificateAuthority issuerCA;
    private CertificateAuthority cAEntityInfo;
    private EntityInfo entityInfo;
    private RequestType requestType;
    private Certificate generatedCertificate;
    protected String subjectUniqueIdentifierValue;
    protected String issuerUniqueIdentifierValue;

    /**
     * 
     * @param version
     * @return
     */
    public CertificateGenerationInfoSetUpData version(final CertificateVersion version) {
        this.version = version;
        return this;
    }

    /**
     * 
     * @param validity
     * @return
     */
    public CertificateGenerationInfoSetUpData validity(final Duration validity) {
        this.validity = validity;
        return this;
    }

    /**
     * 
     * @param subjectUniqueIdentifier
     * @return
     */
    public CertificateGenerationInfoSetUpData subjectUniqueIdentifier(final boolean subjectUniqueIdentifier) {
        this.subjectUniqueIdentifier = subjectUniqueIdentifier;
        return this;
    }

    /**
     * 
     * @param issuerUniqueIdentifier
     * @return
     */
    public CertificateGenerationInfoSetUpData issuerUniqueIdentifier(final boolean issuerUniqueIdentifier) {
        this.issuerUniqueIdentifier = issuerUniqueIdentifier;
        return this;
    }

    /**
     * 
     * @param skewCertificateTime
     * @return
     */
    public CertificateGenerationInfoSetUpData skewCertificateTime(final Duration skewCertificateTime) {
        this.skewCertificateTime = skewCertificateTime;
        return this;
    }

    /**
     * 
     * @param keyGenerationAlgorithm
     * @return
     */
    public CertificateGenerationInfoSetUpData keyGenerationAlgorithm(final Algorithm keyGenerationAlgorithm) {
        this.keyGenerationAlgorithm = keyGenerationAlgorithm;
        return this;
    }

    /**
     * 
     * @param signatureAlgorithm
     * @return
     */
    public CertificateGenerationInfoSetUpData signatureAlgorithm(final Algorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    /**
     * 
     * @param issuerSignatureAlgorithm
     * @return
     */
    public CertificateGenerationInfoSetUpData issuerSignatureAlgorithm(final Algorithm issuerSignatureAlgorithm) {
        this.issuerSignatureAlgorithm = issuerSignatureAlgorithm;
        return this;
    }

    /**
     * 
     * @param certificateExtensions
     * @return
     */
    public CertificateGenerationInfoSetUpData certificateExtensions(final CertificateExtensions certificateExtensions) {
        this.certificateExtensions = certificateExtensions;
        return this;
    }

    /**
     * 
     * @param cSR
     * @return
     */
    public CertificateGenerationInfoSetUpData cSR(final CertificateRequest cSR) {
        this.certificateRequest = cSR;
        return this;
    }

    /**
     * 
     * @param issuerCA
     * @return
     */
    public CertificateGenerationInfoSetUpData issuerCA(final CertificateAuthority issuerCA) {
        this.issuerCA = issuerCA;
        return this;
    }

    /**
     * 
     * @param cAEntityInfo
     * @return
     */
    public CertificateGenerationInfoSetUpData cAEntityInfo(final CertificateAuthority cAEntityInfo) {
        this.cAEntityInfo = cAEntityInfo;
        return this;
    }

    /**
     * 
     * @param entityInfo
     * @return
     */
    public CertificateGenerationInfoSetUpData entityInfo(final EntityInfo entityInfo) {
        this.entityInfo = entityInfo;
        return this;
    }

    /**
     * 
     * @param requestType
     * @return
     */
    public CertificateGenerationInfoSetUpData requestType(final RequestType requestType) {
        this.requestType = requestType;
        return this;
    }

    /**
     * 
     * @param certificate
     * @return
     */
    public CertificateGenerationInfoSetUpData certificate(final Certificate certificate) {
        this.generatedCertificate = certificate;
        return this;
    }

    /**
     * @param subjectUniqueIdentifierValue
     * @return
     */
    public CertificateGenerationInfoSetUpData subjectUniqueIdentifierValue(final String subjectUniqueIdentifierValue) {
        this.subjectUniqueIdentifierValue = subjectUniqueIdentifierValue;
        return this;
    }

    /**
     * @param issuerUniqueIdentifierValue
     * @return
     */
    public CertificateGenerationInfoSetUpData issuerUniqueIdentifierValue(final String issuerUniqueIdentifierValue) {
        this.issuerUniqueIdentifierValue = issuerUniqueIdentifierValue;
        return this;
    }

    /**
     * Method that returns valid CertificateGenerationInfo
     * 
     * @return CertificateGenerationInfo
     */
    public CertificateGenerationInfo build() {
        final CertificateGenerationInfo certificateGenerationInfo = new CertificateGenerationInfo();
        certificateGenerationInfo.setCAEntityInfo(cAEntityInfo);
        certificateGenerationInfo.setCertificateExtensions(certificateExtensions);
        certificateGenerationInfo.setCertificateRequest(certificateRequest);
        certificateGenerationInfo.setEntityInfo(entityInfo);
        certificateGenerationInfo.setIssuerCA(issuerCA);
        certificateGenerationInfo.setIssuerUniqueIdentifier(issuerUniqueIdentifier);
        certificateGenerationInfo.setKeyGenerationAlgorithm(keyGenerationAlgorithm);
        certificateGenerationInfo.setSignatureAlgorithm(signatureAlgorithm);
        certificateGenerationInfo.setIssuerSignatureAlgorithm(issuerSignatureAlgorithm);
        certificateGenerationInfo.setSkewCertificateTime(skewCertificateTime);
        certificateGenerationInfo.setSubjectUniqueIdentifier(subjectUniqueIdentifier);
        certificateGenerationInfo.setRequestType(requestType);
        certificateGenerationInfo.setValidity(validity);
        certificateGenerationInfo.setVersion(version);
        certificateGenerationInfo.setGeneratedCertificate(generatedCertificate);
        certificateGenerationInfo.setSubjectUniqueIdentifierValue(subjectUniqueIdentifierValue);
        certificateGenerationInfo.setIssuerUniqueIdentifierValue(issuerUniqueIdentifierValue);
        return certificateGenerationInfo;
    }
}
