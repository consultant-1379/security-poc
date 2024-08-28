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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test;


import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.RequestType;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateGenerationInfoData;

public class CertificateGenerationInfoSetUpData {

    /**
     * Prepares {@link CertificateGenerationInfoData} to check for equals method.
     *
     * @return {@link CertificateGenerationInfoData} to compare.
     */
    public CertificateGenerationInfoData getCertificateGenerationInfoDataForEqual() {

        final CertificateGenerationInfoData certificateGenerationInfoData = new CertificateGenerationInfoData();

        certificateGenerationInfoData.setId(1);
        certificateGenerationInfoData.setCertificateVersion(CertificateVersion.V3);
        certificateGenerationInfoData.setSkewCertificateTime("P1H");
        certificateGenerationInfoData.setValidity("P2Y");
        certificateGenerationInfoData.setSubjectUniqueIdentifier(true);
        certificateGenerationInfoData.setIssuerUniqueIdentifier(true);
        certificateGenerationInfoData.setSubjectUniqueIdentifierValue("nmsadm1");
        certificateGenerationInfoData.setKeyGenerationAlgorithmData(new AlgorithmSetUpData().getAlgorithmForEqual());
        certificateGenerationInfoData.setSignatureAlgorithmData(new AlgorithmSetUpData().getAlgorithmForEqual());
        certificateGenerationInfoData.setIssuerSignatureAlgorithmData(new AlgorithmSetUpData().getAlgorithmForEqual());
        certificateGenerationInfoData.setRequestType(RequestType.NEW);
        certificateGenerationInfoData.setCertificateExtensionsJSONData("CertificateExtensions");
        certificateGenerationInfoData.setcAEntityInfo(new CertificateAuthoritySetUpData().getCertificateAuthotityForEqual());
        certificateGenerationInfoData.setIssuerCA(new CertificateAuthoritySetUpData().getCertificateAuthotityForEqual());
        certificateGenerationInfoData.setEntityInfo(new EntitySetUpData().getEntityForEqual());
        certificateGenerationInfoData.setCertificateRequestData(new CertificateRequestSetUpData().getCSRForEqual());
        certificateGenerationInfoData.setCertificateData(new CertificateSetUpData().getCertificateForEqual());

        return certificateGenerationInfoData;
    }

    /**
     * Prepares {@link CertificateGenerationInfoData} to check for equals method.
     *
     * @return {@link CertificateGenerationInfoData} to compare.
     */
    public CertificateGenerationInfoData getCertificateGenerationInfoDataForNotEqual() {

        final CertificateGenerationInfoData certificateGenerationInfoData = new CertificateGenerationInfoData();

        certificateGenerationInfoData.setId(2);
        certificateGenerationInfoData.setCertificateVersion(CertificateVersion.V3);
        certificateGenerationInfoData.setSkewCertificateTime("P1H");
        certificateGenerationInfoData.setValidity("P2Y");
        certificateGenerationInfoData.setSubjectUniqueIdentifier(false);
        certificateGenerationInfoData.setIssuerUniqueIdentifier(false);
        certificateGenerationInfoData.setSubjectUniqueIdentifierValue("nmsadm123");
        certificateGenerationInfoData.setKeyGenerationAlgorithmData(new AlgorithmSetUpData().getAlgorithmForNotEqual());
        certificateGenerationInfoData.setSignatureAlgorithmData(new AlgorithmSetUpData().getAlgorithmForNotEqual());
        certificateGenerationInfoData.setIssuerSignatureAlgorithmData(new AlgorithmSetUpData().getAlgorithmForNotEqual());
        certificateGenerationInfoData.setRequestType(RequestType.RENEW);
        certificateGenerationInfoData.setCertificateExtensionsJSONData("CertificateExtensions");
        certificateGenerationInfoData.setcAEntityInfo(new CertificateAuthoritySetUpData().getCertificateAuthotityForNotEqual());
        certificateGenerationInfoData.setIssuerCA(new CertificateAuthoritySetUpData().getCertificateAuthotityForNotEqual());
        certificateGenerationInfoData.setEntityInfo(new EntitySetUpData().getEntityForNotEqual());
        certificateGenerationInfoData.setCertificateRequestData(new CertificateRequestSetUpData().getCSRForNotEqual());
        certificateGenerationInfoData.setCertificateData(new CertificateSetUpData().getCertificateForNotEqual());

        return certificateGenerationInfoData;
    }
}
