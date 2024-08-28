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

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;

public class CertificateAuthoritySetUpData {

    private static final String entityName = "ENMSecurityCA";

    /**
     * Prepares {@link CertificateAuthorityData} to check for equals method.
     * 
     * @return {@link CertificateAuthorityData} to compare.
     */
    public CertificateAuthorityData getCertificateAuthotityForEqual() {
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();

        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        certificateDatas.add(new CertificateSetUpData().getCertificateForEqual());
        CertificateAuthorityData issuerCertificateAuthorityData = new CertificateAuthorityData();
        issuerCertificateAuthorityData.setId(1);
        issuerCertificateAuthorityData.setName(entityName);
        issuerCertificateAuthorityData.setCreatedDate(new Date("1/01/2016"));
        issuerCertificateAuthorityData.setModifiedDate(new Date("1/01/2016"));
        issuerCertificateAuthorityData.setPublishToCDPS(Boolean.TRUE);
        certificateAuthorityData.setRootCA(Boolean.TRUE);
        certificateAuthorityData.setName(entityName);
        certificateAuthorityData.setStatus(CAStatus.ACTIVE);
        certificateAuthorityData.setCertificateDatas(certificateDatas);
        certificateAuthorityData.setSubjectDN(new SubjectSetUpData().getSubjectForCreate().toASN1String());
        certificateAuthorityData.setSubjectAltName(JsonUtil.getJsonFromObject(new SubjectAltNameSetUpData().getSANForCreate()));
        certificateAuthorityData.setIssuerCA(issuerCertificateAuthorityData );
        certificateAuthorityData.setModifiedDate(new Date("1/12/2016"));
        certificateAuthorityData.setPublishToCDPS(Boolean.TRUE);
        certificateAuthorityData.setCreatedDate(new Date("1/01/2016"));
        return certificateAuthorityData;
    }

    /**
     * Prepares {@link CertificateAuthorityData} to check for equals method.
     * 
     * @return {@link CertificateAuthorityData} to compare.
     */
    public CertificateAuthorityData getCertificateAuthotityForNotEqual() {
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();

        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        certificateDatas.add(new CertificateSetUpData().getCertificateForNotEqual());
        CertificateAuthorityData issuerCertificateAuthorityData = new CertificateAuthorityData();
        issuerCertificateAuthorityData.setId(5);
        issuerCertificateAuthorityData.setName(entityName);
        issuerCertificateAuthorityData.setCreatedDate(new Date("2/01/2016"));
        issuerCertificateAuthorityData.setModifiedDate(new Date("2/01/2016"));
        issuerCertificateAuthorityData.setPublishToCDPS(Boolean.FALSE);
        certificateAuthorityData.setId(2);
        certificateAuthorityData.setRootCA(Boolean.FALSE);
        certificateAuthorityData.setName(entityName);
        certificateAuthorityData.setStatus(CAStatus.DELETED);
        certificateAuthorityData.setCertificateDatas(certificateDatas);
        certificateAuthorityData.setSubjectDN(new SubjectSetUpData().getSubjectForCreate().toASN1String());
        certificateAuthorityData.setSubjectAltName(JsonUtil.getJsonFromObject(new SubjectAltNameSetUpData().getSANForCreate()));
        certificateAuthorityData.setIssuerCA(issuerCertificateAuthorityData );
        certificateAuthorityData.setModifiedDate(new Date("2/12/2016"));
        certificateAuthorityData.setPublishToCDPS(Boolean.FALSE);
        certificateAuthorityData.setCreatedDate(new Date("2/01/2016"));
        return certificateAuthorityData;
    }
}
