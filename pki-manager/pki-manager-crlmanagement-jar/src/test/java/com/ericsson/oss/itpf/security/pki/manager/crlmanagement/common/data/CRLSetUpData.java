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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.data;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;

/**
 * This is the class to setup data for CRL .
 */
public class CRLSetUpData {

    private static long id = 1033232325;
    private static SimpleDateFormat sd = new SimpleDateFormat("dd/MM/yyyy");

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Method to get values to CRLInfo.
     * 
     * @return CRLInfo
     */
    public static CRLInfo getCRLInfo(CRLStatus status) {
        final CRLInfo crl = new CRLInfo();
        CRLNumber cRLNumber = new CRLNumber();
        cRLNumber.setSerialNumber(Constants.CRL_SERIAL_NUMBER);
        crl.setCrlNumber(cRLNumber);
        crl.setId(id);
        try {
            crl.setIssuerCertificate(getIssuerCertificate());
        } catch (CertificateException | NoSuchProviderException | IOException e) {
            e.printStackTrace();
        }
        crl.setNextUpdate(new Date());
        crl.setStatus(status);
        crl.setThisUpdate(new Date());
        return crl;
    }

    /**
     * Method to get values to CACertificateIdentifier.
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
     * Method to get values to Certificate.
     * 
     * @return Certificate
     */

    public static Certificate getCertificate(String serialNumber) {

        CertificateAuthority issuer = new CertificateAuthority();
        Certificate certificate = new Certificate();
        certificate.setId(id);
        certificate.setIssuedTime(new Date());
        certificate.setIssuer(issuer);
        try {
            certificate.setIssuerCertificate(getIssuerCertificate());
        } catch (CertificateException | NoSuchProviderException | IOException e) {
            e.printStackTrace();
        }
        certificate.setNotAfter(getNotAfterDate());
        certificate.setNotBefore(new Date());
        certificate.setSerialNumber(serialNumber);
        return certificate;
    }

    /**
     * Method to get values to CAEntity.
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
     * Method to get values to CAEntityData.
     * 
     * @return CAEntityData.
     */

    public static CAEntityData getCAEntityData() {
        CAEntityData caEntityData = new CAEntityData();
        Set<CAEntityData> associated = new HashSet<CAEntityData>();
        associated.add(caEntityData);
        caEntityData.setAssociated(associated);
        CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        caEntityData.setId(id);
        caEntityData.setExternalCA(true);
        return caEntityData;

    }

    /**
     * Method to get Certificate.
     * 
     * @return Certificate.
     */
    private static Certificate getIssuerCertificate() throws CertificateException, NoSuchProviderException, IOException {
        Certificate issuerCertificate = new Certificate();
        issuerCertificate.setId(id);
        issuerCertificate.setSerialNumber(Constants.VALID_CERTIFICATE_SERIALNUMBER);
        issuerCertificate.setStatus(CertificateStatus.ACTIVE);
        issuerCertificate.setNotAfter(getNotAfterDate());
        issuerCertificate.setX509Certificate(getX509Certificate());
        return issuerCertificate;
    }

    /**
     * Method to get NotAfterDate
     */
    private static Date getNotAfterDate() {
        Date date = null;
        try {
            date = sd.parse(Constants.NOT_AFTER_DATE);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return date;
    }

    /**
     * This method is used to load a test certificate and converts it into X509Certificate.
     * 
     * @return X509Certificate
     * @throws IOException
     *             thrown when FileInputStream is improperly closed.
     * @throws CertificateException
     *             thrown when there is any error while generating the certificate.
     * @throws NoSuchProviderException
     *             thrown when the given provider is not found
     */
    private static X509Certificate getX509Certificate() throws IOException, CertificateException, NoSuchProviderException {
        final FileInputStream fin = new FileInputStream("src/test/resources/MyRoot.crt");
        final CertificateFactory f = CertificateFactory.getInstance("X.509", "BC");
        final X509Certificate x509certificate = (X509Certificate) f.generateCertificate(fin);
        return x509certificate;

    }

    /**
     * Method to prepareCACertificateIdentifierList
     * 
     */
    public static List<CACertificateIdentifier> getCACertificateIdentifierList() {

        List<CACertificateIdentifier> caCertificateIdentifierList = new ArrayList<CACertificateIdentifier>();

        CACertificateIdentifier caCertificateIdentifier1 = new CACertificateIdentifier();
        caCertificateIdentifier1.setCaName("ENM_RootCA");
        caCertificateIdentifier1.setCerficateSerialNumber("12345");

        CACertificateIdentifier caCertificateIdentifier2 = new CACertificateIdentifier();
        caCertificateIdentifier2.setCaName("ENM_RootCA");
        caCertificateIdentifier2.setCerficateSerialNumber("12345");

        caCertificateIdentifierList.add(caCertificateIdentifier1);
        caCertificateIdentifierList.add(caCertificateIdentifier2);

        return caCertificateIdentifierList;
    }

    /**
     * Method to prepareCACertificateIdentifierListEmpty
     * 
     */
    public static List<CACertificateIdentifier> getCACertificateIdentifierListEmpty() {

        List<CACertificateIdentifier> caCertificateIdentifierList = new ArrayList<CACertificateIdentifier>();

        return caCertificateIdentifierList;
    }

    public static Map<CACertificateIdentifier, CRLInfo> getCACertCRLInfoMap() {
        final Map<CACertificateIdentifier, CRLInfo> caCertCRLInfoMap = new HashMap<CACertificateIdentifier, CRLInfo>();
        final CRLInfo latestCRL = new CRLInfo();
        latestCRL.setStatus(CRLStatus.LATEST);
        latestCRL.setNextUpdate(new Date());
        caCertCRLInfoMap.put(new CACertificateIdentifier("CAName1", "1a2s3d1"), latestCRL);

        final CRLInfo expiredCRL = new CRLInfo();
        expiredCRL.setStatus(CRLStatus.EXPIRED);
        caCertCRLInfoMap.put(new CACertificateIdentifier("CAName2", "1a2s3d2"), expiredCRL);

        caCertCRLInfoMap.put(new CACertificateIdentifier("CAName3", "1a2s3d3"), null);

        return caCertCRLInfoMap;
    }
}
