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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test;

import java.util.*;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;

public class MockData {

    private MockData() {

    }

    private static CRLInfo cRLInfo;

    /**
     * Method to prepare CACertificateIdentifier.
     * 
     * @return CACertificateIdentifier.
     */
    public static CACertificateIdentifier getCACertificateIdentifier(final String caName, final String serialNumber) {
        CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName(caName);
        caCertificateIdentifier.setCerficateSerialNumber(serialNumber);
        return caCertificateIdentifier;

    }

    /**
     * Method to prepare Certificate data.
     * 
     * @return CertificateData entity.
     */

    public static CertificateData getCertificateData(String serialNumber) {
        final CertificateData certificateData = new CertificateData();
        certificateData.setNotAfter(new Date());
        certificateData.setNotAfter(new Date());
        certificateData.setStatus(CertificateStatus.ACTIVE);
        certificateData.setSerialNumber(serialNumber);
        return certificateData;
    }

    /**
     * Method to prepare CertificateAuthorityData.
     * 
     * @return CertificateAuthorityData.
     */

    public static CertificateAuthorityData getCertificateAuthorityData(final Set<CertificateData> certificates) {
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setCertificateDatas(certificates);
        certificateAuthorityData.setName(Constants.CA_NAME);
        certificateAuthorityData.setRootCA(true);
        certificateAuthorityData.setStatus(CAStatus.ACTIVE);
        certificateAuthorityData.setIssuerCA(null);
        return certificateAuthorityData;
    }

    /**
     * Method to prepare Certificate.
     * 
     * @return Certificate.
     */

    public static Certificate getCertificate(String serialNumber) {
        Certificate certificate = new Certificate();
        certificate.setSerialNumber(serialNumber);
        return certificate;
    }

    /**
     * Method to prepare CertificateAuthority.
     * 
     * @return CertificateAuthority
     */
    public static CertificateAuthority getCertificateAuthority(final boolean isRootCA, Certificate certificate, String certificateStatus) {
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        cRLInfo = new CRLInfo();
        cRLInfo.setIssuerCertificate(certificate);
        List<CRLInfo> cRLInfoList = new ArrayList<CRLInfo>();
        List<Certificate> inActiveCertificateList = new ArrayList<Certificate>();
        certificateAuthority.setRootCA(isRootCA);
        if (certificateStatus.equals(Constants.STATUS_ACTIVE)) {
            certificateAuthority.setActiveCertificate(certificate);
        } else {
            inActiveCertificateList.add(certificate);
            certificateAuthority.setInActiveCertificates(inActiveCertificateList);
        }
        certificateAuthority.setCrlInfo(cRLInfoList);
        return certificateAuthority;
    }

    /**
     * Method to addCRLInfo to cRLInfoList.
     */
    public static void addCRLInfo(CertificateAuthority certificateAuthority) {
        List<CRLInfo> cRLInfoList = certificateAuthority.getCrlInfo();
        cRLInfo.setStatus(CRLStatus.LATEST);
        cRLInfoList.add(cRLInfo);
    }

}
