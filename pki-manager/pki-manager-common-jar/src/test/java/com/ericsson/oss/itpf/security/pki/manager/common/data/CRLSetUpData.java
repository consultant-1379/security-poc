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
package com.ericsson.oss.itpf.security.pki.manager.common.data;

/**
 *  This class is used to set up initial test data for CRL
 */
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.CommonConstants;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

public class CRLSetUpData {

    private static long id = 1033232325;
    private static SimpleDateFormat sd = new SimpleDateFormat("dd/MM/yyyy");

    /**
     * Method to get CRLInfo.
     *
     * @return CRLInfo
     */
    public static CRLInfo getCRLInfo(final CRLStatus status, final boolean isMatchingCRL) {
        final CRLInfo crl = new CRLInfo();
        CRLNumber cRLNumber = new CRLNumber();
        cRLNumber.setSerialNumber(CommonConstants.CRL_SERIAL_NUMBER);
        crl.setCrlNumber(cRLNumber);
        crl.setId(id);
        try {
            crl.setIssuerCertificate(getIssuerCertificate(CommonConstants.VALID_CERTIFICATE_SERIALNUMBER));
            if (!isMatchingCRL) {
                crl.setIssuerCertificate(getIssuerCertificate(CommonConstants.INVALID_CERTIFICATE_SERIALNUMBER));

            }
        } catch (CertificateException | NoSuchProviderException | IOException e) {
            e.printStackTrace();
        }
        crl.setNextUpdate(new Date());
        crl.setStatus(status);
        crl.setThisUpdate(new Date());
        return crl;
    }

    /**
     * Method to get CACertificateIdentifier object.
     *
     * @return CACertificateIdentifier.
     */
    public static CACertificateIdentifier getCACertificateIdentifier(String caName, String serialNumber) {
        CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName(caName);
        caCertificateIdentifier.setCerficateSerialNumber(serialNumber);
        return caCertificateIdentifier;
    }

    /**
     * Method to get Certificate.
     *
     * @return Certificate
     */
    public static Certificate getCertificate(String serialNumber, CertificateStatus status) {

        final CertificateAuthority issuer = new CertificateAuthority();
        final Certificate certificate = new Certificate();
        certificate.setId(id);
        certificate.setIssuedTime(new Date());
        certificate.setIssuer(issuer);
        try {
            certificate.setIssuerCertificate(getIssuerCertificate(CommonConstants.VALID_CERTIFICATE_SERIALNUMBER));
        } catch (CertificateException | NoSuchProviderException | IOException e) {
            e.printStackTrace();
        }
        if (status.equals(CertificateStatus.EXPIRED)) {
            try {
                certificate.setNotAfter(sd.parse("01/01/2000"));
            } catch (ParseException e) {
                e.printStackTrace();
            }
        } else {
            certificate.setNotAfter(getNotAfterDate());
        }
        certificate.setNotBefore(new Date());
        certificate.setSerialNumber(serialNumber);
        certificate.setStatus(status);
        return certificate;
    }

    /**
     * Method to get CAEntity.
     *
     * @return CAEntity.
     */
    public static CAEntity getCaEntity(CertificateAuthority certificateAuthority) {
        CAEntity caEntity = new CAEntity();
        caEntity.setCertificateAuthority(certificateAuthority);
        caEntity.setType(EntityType.CA_ENTITY);
        return caEntity;
    }

    /**
     * Method to get CAEntityData.
     *
     * @return CAEntityData.
     */
    public static CAEntityData getCAEntityData() {
        final CAEntityData caEntityData = new CAEntityData();
        final Set<CAEntityData> associated = new HashSet<CAEntityData>();
        associated.add(caEntityData);
        caEntityData.setAssociated(associated);
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        caEntityData.setId(id);
        caEntityData.setExternalCA(true);
        return caEntityData;
    }

    /**
     * Method to get issuerCertificate.
     *
     * @return CAEntityData.
     */
    private static Certificate getIssuerCertificate(final String serialNumber) throws CertificateException, NoSuchProviderException, IOException {
        final Certificate issuerCertificate = new Certificate();
        issuerCertificate.setId(id);
        issuerCertificate.setSerialNumber(serialNumber);
        issuerCertificate.setStatus(CertificateStatus.ACTIVE);
        issuerCertificate.setNotAfter(getNotAfterDate());
        return issuerCertificate;
    }

    /**
     * Method to get NotAfterDate
     */
    private static Date getNotAfterDate() {
        Date date = null;
        try {
            date = sd.parse(CommonConstants.NOT_AFTER_DATE);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return date;
    }

    /**
     * Method to get CRLInfoData
     */
    public static CRLInfoData getCRLInfoData() {
        CRLInfoData crlInfoDataExpire = new CRLInfoData();
        crlInfoDataExpire.setNextUpdate(new Date());

        return crlInfoDataExpire;
    }

    /**
     * Method to get CACertificateIdentifier
     */
    public static CACertificateIdentifier getCACertificateIdentifier() {
        CACertificateIdentifier caCertId = new CACertificateIdentifier();
        caCertId.setCaName("caName");
        caCertId.setCerficateSerialNumber("cerficateSerialNumber");

        return caCertId;
    }

    /**
     * Method to get CACertificateIdentifier and CRLInfo
     */
    public static HashMap<CACertificateIdentifier, CRLInfo> getCACertIdentifierCRLInfoMap() {
        HashMap<CACertificateIdentifier, CRLInfo> caCrlInfoHashMap = new HashMap<CACertificateIdentifier, CRLInfo>();
        caCrlInfoHashMap.put(getCACertificateIdentifier(), new CRLInfo());

        return caCrlInfoHashMap;
    }

    /**
     * Method to get CertificateData
     */
    public static CertificateData getCertificateData() {
        CertificateData cData = new CertificateData();
        cData.setSerialNumber("serialNumber");
        cData.setId(1L);
        return cData;
    }

    /**
     * Method to get CertificateData Set
     */
    public static HashSet<CertificateData> getCertificateDataSet() {
        HashSet<CertificateData> certificateDataSet = new HashSet<CertificateData>();
        certificateDataSet.add(getCertificateData());

        return certificateDataSet;
    }

    /**
     * Method to get CertificateAuthorityData
     */
    public static CertificateAuthorityData getCertificateAuthorityData() {
        CertificateAuthorityData cAuthorityData = new CertificateAuthorityData();
        cAuthorityData.setCertificateDatas(getCertificateDataSet());

        return cAuthorityData;
    }

    /**
     * Method to get Certificate
     */
    public static Certificate getCertificate() {
        Certificate certificate = new Certificate();
        certificate.setId(1L);

        return certificate;
    }

    /**
     * Method to get CRLInfo
     */
    public static CRLInfo getCRLInfo() {
        CRLInfo cInfo = new CRLInfo();
        cInfo.setIssuerCertificate(getCertificate());

        return cInfo;
    }

    /**
     * Method to get CRLInfo
     */
    public static CRLInfo getCRLInfoExpired() {
        CRLInfo crlInfo = new CRLInfo();
        crlInfo.setId(123456);
        crlInfo.setStatus(CRLStatus.EXPIRED);

        return crlInfo;
    }

    public static CAEntityData getCAEntityDataForCACertCRLInfoHashMap() {
        final CertificateData validCertData = new CertificateData();
        validCertData.setSerialNumber(CommonConstants.VALID_CERTIFICATE_SERIALNUMBER);
        validCertData.setStatus(CertificateStatus.ACTIVE.getId());
        validCertData.setNotAfter(getNotAfterDate());

        final CertificateData certDataWithIssuerrevoked = new CertificateData();
        certDataWithIssuerrevoked.setSerialNumber(CommonConstants.VALID_CERTIFICATE_WITH_ISSUER_REVOKED_SERIALNUMBER);
        certDataWithIssuerrevoked.setStatus(CertificateStatus.ACTIVE.getId());
        CertificateData issuerCert = new CertificateData();
        issuerCert.setStatus(CertificateStatus.REVOKED.getId());
        certDataWithIssuerrevoked.setIssuerCertificate(issuerCert);
        certDataWithIssuerrevoked.setNotAfter(getNotAfterDate());

        final CertificateAuthorityData certAuthData = new CertificateAuthorityData();
        certAuthData.setName(CommonConstants.CA_NAME);
        certAuthData.getCertificateDatas().add(validCertData);
        certAuthData.getCertificateDatas().add(certDataWithIssuerrevoked);

        final CRLInfoData crlInfoData = new CRLInfoData();
        crlInfoData.setCertificateData(validCertData);
        certAuthData.getcRLDatas().add(crlInfoData);

        final CrlGenerationInfoData crlGenerationInfoData = new CrlGenerationInfoData();
        certAuthData.getCrlGenerationInfo().add(crlGenerationInfoData);
        CAEntityData caEntityData = new CAEntityData();
        caEntityData.setCertificateAuthorityData(certAuthData);

        return caEntityData;
    }
}
