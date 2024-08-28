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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test;

/**
 *  This is the class to setup data for CRL .
 */
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.xml.datatype.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator.RevokedCertificatesInfo;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl.CAEntityManager;

public class CRLSetUpData {

    private static int crlSerialNumber = 123456;
    private static long id = 1033232325;
    private static Date nextUpdate;
    private static Date thisUpdate;
    private static Certificate issuerCertificate;
    private static String caName = "ERBS_1";
    private static String cerficateSerialNumber = "1508f262d31";
    private static CACertificateIdentifier caCertificateIdentifier;
    private static Certificate certificate;
    private static CAEntityManager caEntity;
    private static SimpleDateFormat sd = new SimpleDateFormat("dd/MM/yyyy");
    private static Date notAfterDate = null;
    private static final String caEntityName = "ENM_CA";
    private static Duration duration;
    private static final Integer serialNumber = 1000;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Method to get values to CRLInfo.
     * 
     * @return CRLInfo
     */
    public static CRLInfo getCRLInfo(String status) {
        final CRLInfo crl = new CRLInfo();
        CRLNumber crlNumber = new CRLNumber();
        crlNumber.setSerialNumber(serialNumber);
        issuerCertificate = getCertificate();
        crl.setCrlNumber(crlNumber);
        crl.setId(id);
        crl.setIssuerCertificate(issuerCertificate);
        crl.setNextUpdate(nextUpdate);
        if (status.equals("LATEST")) {
            crl.setStatus(CRLStatus.LATEST);
        } else {
            crl.setStatus(CRLStatus.INVALID);
        }
        crl.setThisUpdate(thisUpdate);
        return crl;
    }

    /**
     * Method to get values to CRLInfoForThrowing Exception.
     * 
     * @return CRLInfo
     */

    public static CRLInfo fillCRLForNoLatestCRLException() {
        final CRLInfo crl = new CRLInfo();
        CRLNumber crlNumber = new CRLNumber();
        issuerCertificate = new Certificate();
        issuerCertificate.setId(id);
        issuerCertificate.setSerialNumber(cerficateSerialNumber);
        crlNumber.setSerialNumber(crlSerialNumber);
        crl.setCrlNumber(crlNumber);
        crl.setId(id);
        crl.setIssuerCertificate(issuerCertificate);
        crl.setNextUpdate(nextUpdate);
        crl.setStatus(CRLStatus.INVALID);
        crl.setThisUpdate(thisUpdate);
        return crl;
    }

    /**
     * Method to get values to CACertificateIdentifier.
     * 
     * @return CACertificateIdentifier.
     */

    public static CACertificateIdentifier caCertificateIdentifierFill() {
        caCertificateIdentifier = new CACertificateIdentifier(cerficateSerialNumber, cerficateSerialNumber);
        caCertificateIdentifier.setCaName(caName);
        caCertificateIdentifier.setCerficateSerialNumber(cerficateSerialNumber);
        return caCertificateIdentifier;
    }

    /**
     * Method to get values to Certificate.
     * 
     * @return Certificate
     */

    public static Certificate getCertificate() {

        CertificateAuthority issuer = new CertificateAuthority();
        certificate = new Certificate();
        certificate.setId(id);
        certificate.setIssuedTime(new Date());
        certificate.setIssuer(issuer);
        issuerCertificate = new Certificate();
        issuerCertificate.setSerialNumber(cerficateSerialNumber);
        issuerCertificate.setStatus(CertificateStatus.ACTIVE);
        issuerCertificate.setNotAfter(getNotAfterDate());
        certificate.setIssuerCertificate(issuerCertificate);
        certificate.setNotAfter(getNotAfterDate());
        certificate.setNotBefore(new Date());
        certificate.setSerialNumber("1508f262d31");
        certificate.setStatus(CertificateStatus.ACTIVE);
        certificate.setSubject(getSubject());

        return certificate;
    }

    /**
     * Method to get values to CAEntity.
     * 
     * @return CAEntity.
     */

    public static CAEntityManager getCaEntity(CertificateAuthority certificateAuthority) {
        caEntity = new CAEntityManager();
        return caEntity;
    }

    /**
     * Method to get NotAfterDate.
     * 
     * @return Date.
     */
    public static Date getNotAfterDate() {
        try {
            notAfterDate = sd.parse("31/12/9999");
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return notAfterDate;
    }

    /**
     * Method to get nextUpdate.
     * 
     * @return Date.
     */
    public static Date getNextAfter() {
        try {
            nextUpdate = sd.parse("31/12/8569");
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return nextUpdate;
    }

    /**
     * Method to get CACertificateIdentifier.
     * 
     * @return CACertificateIdentifier.
     */
    public static CACertificateIdentifier getCACertificateIdentifier() {
        caCertificateIdentifier = new CACertificateIdentifier("CaName", "CaName");
        caCertificateIdentifier.setCaName(caEntityName);
        caCertificateIdentifier.setCerficateSerialNumber(cerficateSerialNumber);
        return caCertificateIdentifier;

    }

    /**
     * Method to get CrlGenerationInfo.
     * 
     * @return CrlGenerationInfo.
     */
    public static CrlGenerationInfo getCrlGenerationInfo() {
        try {
            duration = DatatypeFactory.newInstance().newDuration("P42D");
        } catch (DatatypeConfigurationException e) {
            e.printStackTrace();
        }
        ArrayList<Certificate> inActiveCertificates = new ArrayList<Certificate>();
        inActiveCertificates.add(getCertificate());
        CrlGenerationInfo CrlGenerationInfo = new CrlGenerationInfo();
        CrlGenerationInfo.setCaCertificates(inActiveCertificates);
        CrlGenerationInfo.setId(crlSerialNumber);
        CrlGenerationInfo.setValidityPeriod(duration);
        CrlExtensions crlExtensions = new CrlExtensions();
        AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess();
        authorityInformationAccess.setCritical(true);
        crlExtensions.setAuthorityInformationAccess(authorityInformationAccess);
        AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
        authorityKeyIdentifier.setCritical(true);
        crlExtensions.setAuthorityKeyIdentifier(authorityKeyIdentifier);
        IssuingDistributionPoint issuingDistributionPoint = new IssuingDistributionPoint();
        issuingDistributionPoint.setCritical(true);
        crlExtensions.setIssuingDistributionPoint(issuingDistributionPoint);
        CrlGenerationInfo.setCrlExtensions(crlExtensions);
        CrlGenerationInfo.setVersion(CRLVersion.V2);
        return CrlGenerationInfo;
    }

    /**
     * Method to get CertificateAuthority
     * 
     * @return CertificateAuthority
     */

    public static CertificateAuthority getCertificateAuthority() {
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setActiveCertificate(getCertificate());
        certificateAuthority.setRootCA(true);
        certificateAuthority.setCrlGenerationInfo(getCrlGenerationInfoList());
        Subject subject = getSubject();
        certificateAuthority.setSubject(subject);
        return certificateAuthority;

    }

    /**
     * @return
     */
    private static Subject getSubject() {
        Subject subject = new Subject();
        List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        SubjectField subjectField = new SubjectField();
        SubjectFieldType type = SubjectFieldType.COMMON_NAME;
        subjectField.setType(type);
        subjectField.setValue(caEntityName);
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        return subject;
    }

    /**
     * Method to get CertificateAuthority
     * 
     * @return CertificateAuthority
     */

    public static CertificateAuthority getCertificateAuthorityForX509(CRLInfo cRLInfo) {
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setActiveCertificate(getCertificate());
        certificateAuthority.isRootCA();
        if (cRLInfo != null) {
            certificateAuthority.setCrlInfo(getCrlInfoList());
        }
        return certificateAuthority;

    }

    /**
     * Method to get CertificateAuthorityData.
     * 
     * @return CertificateAuthorityData.
     */
    public static CertificateAuthorityData getCertificateAuthorityData() {
        CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        Set<CRLInfoData> cRLDatas = new HashSet<CRLInfoData>();
        CRLInfoData cRLInfoData = new CRLInfoData();
        cRLInfoData.setStatus(CRLStatus.LATEST);
        CertificateData certificateData = new CertificateData();
        certificateData.setSerialNumber(cerficateSerialNumber);
        cRLInfoData.setCertificateData(certificateData);
        cRLDatas.add(cRLInfoData);
        certificateAuthorityData.setCrlDatas(cRLDatas);
        return certificateAuthorityData;

    }

    /**
     * Method to get List<RevokedCertificatesInfo>.
     * 
     * @return List<RevokedCertificatesInfo>.
     */
    public static List<RevokedCertificatesInfo> getRevokedCertificatesInfoList() {
        final List<RevokedCertificatesInfo> revokedCertificatesInfoList = new ArrayList<RevokedCertificatesInfo>();
        RevokedCertificatesInfo revokedCertificatesInfo = new RevokedCertificatesInfo();
        revokedCertificatesInfo.setInvalidityDate(new Date());
        revokedCertificatesInfo.setRevocationDate(new Date());
        revokedCertificatesInfo.setRevocationReason(2);
        revokedCertificatesInfo.setSerialNumber("123");
        revokedCertificatesInfoList.add(revokedCertificatesInfo);
        return revokedCertificatesInfoList;
    }

    /**
     * Method to get CRLNumber.
     * 
     * @return CRLNumber.
     */
    public static CRLNumber getCRLNumber() {
        final CRLNumber cRLNumber = new CRLNumber();
        cRLNumber.setCritical(true);
        cRLNumber.setSerialNumber(01);
        return cRLNumber;
    }

    /**
     * Method to set data to X509CRL.
     * 
     * @return X509CRL.
     * @throws CRLException
     */
    public static X509CRL getX509CRL(final String filename) throws IOException, CertificateException, CRLException {
        final FileInputStream fin = new FileInputStream(filename);
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        final X509CRL crl = (X509CRL) certificateFactory.generateCRL(fin);
        return crl;

    }

    /**
     * Method to get List<CrlGenerationInfo>.
     * 
     * @return List<CrlGenerationInfo>.
     */
    public static List<CRLInfo> getCrlInfoList() {
        List<CRLInfo> CrlInfoList = new ArrayList<CRLInfo>();
        CrlInfoList.add(getCRLInfo("LATEST"));
        return CrlInfoList;
    }

    /**
     * Method to get List<CrlGenerationInfo>.
     * 
     * @return List<CrlGenerationInfo>.
     */
    public static List<CrlGenerationInfo> getCrlGenerationInfoList() {
        List<CrlGenerationInfo> CrlGenerationInfoList = new ArrayList<CrlGenerationInfo>();
        CrlGenerationInfoList.add(getCrlGenerationInfo());
        return CrlGenerationInfoList;
    }

    /**
     * Method to set data to X509Certificate.
     * 
     * @return X509Certificate.
     */
    public static X509Certificate getX509Certificate(final String filename) throws IOException, CertificateException {
        final FileInputStream fin = new FileInputStream(filename);
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        final X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fin);
        return certificate;
    }

    // /**
    // * Method to get Extension.
    // * @return Extension.
    // */
    // public static Extension getExtension(){
    // ASN1ObjectIdentifier extnId=new ASN1ObjectIdentifier("2.5.29.9");
    // @SuppressWarnings("deprecation")
    // ASN1Boolean critical=new ASN1Boolean(true);
    // ASN1OctetString value=ASN1OctetString.getInstance(extnId);
    // Extension authorityKeyIdentifierExtension = new Extension(extnId, critical, value);
    // return authorityKeyIdentifierExtension;
    //
    // }
    /**
     * Method to set data to CertificateGenerationInfo.
     * 
     * @return CertificateGenerationInfo.
     */
    public static CertificateGenerationInfo getCertificateGenerationInfo() {
        final CertificateGenerationInfo certificateGenerationInfo = new CertificateGenerationInfo();
        certificateGenerationInfo.setIssuerCA(getCertificateAuthority());
        return certificateGenerationInfo;

    }

    /**
     * Method to generate key pair using given algorithm and key size.
     *
     * @param keyPairAlgorithm
     *            algorithm to generate the key pair.
     * @param KeySize
     *            key size for the key to be generated.
     * @return generated key pair.
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair generateKeyPair(final String keyPairAlgorithm, final int KeySize) throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        final KeyPairGenerator gen = KeyPairGenerator.getInstance(keyPairAlgorithm);
        gen.initialize(KeySize);
        return gen.generateKeyPair();
    }

    /**
     * Method to set data to IssuingDistributionPoint.
     * 
     * @return IssuingDistributionPoint.
     */
    public static IssuingDistributionPoint getIssuingDistributionPoint() {
        final IssuingDistributionPoint issuingDistributionPoint = new IssuingDistributionPoint();
        List<ReasonFlag> reasonFlags = new ArrayList<ReasonFlag>();
        ReasonFlag reasonFlag = ReasonFlag.SUPERSEDED;
        reasonFlags.add(reasonFlag);
        DistributionPointName distributionPoint = new DistributionPointName();
        distributionPoint.setNameRelativeToCRLIssuer("C=DE,O=Organiztion");
        List<String> fullName = new ArrayList<String>();
        fullName.add("FullName");
        distributionPoint.setFullName(fullName);
        issuingDistributionPoint.setDistributionPoint(distributionPoint);
        issuingDistributionPoint.setOnlySomeReasons(reasonFlags);
        return issuingDistributionPoint;

    }

}
