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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.*;
import java.util.*;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * Base class for common functionality.
 * 
 */
public class SetUPData {

    public static final String ROOT_CA_NAME = "ENMRootCA";
    public static final String SUB_CA_NAME = "ENMSubCA";
    public static final String ENTITY_NAME = "Entity";
    public static final String SIGNATURE_ALGORITHM = "SHA1WITHRSA";
    public static final String KEY_GEN_ALGORITHM = "RSA";
    public static final String CERTIFICATE_TYPE = "X.509";

    private static SubjectSetUPData subjectData = new SubjectSetUPData();

    /**
     * Map X509Certificate object to Certificate model.
     * 
     * @param x509certificate
     *            X509Certificate that to be mapped to model.
     * @return Certificate model mapped from X509Certificate.
     */
    public Certificate toCertificate(final X509Certificate x509certificate) {
        final Certificate certificate = new Certificate();
        certificate.setX509Certificate(x509certificate);
        certificate.setIssuedTime(x509certificate.getNotBefore());
        certificate.setNotBefore(x509certificate.getNotBefore());
        certificate.setNotAfter(x509certificate.getNotAfter());
        certificate.setSerialNumber(x509certificate.getSerialNumber().toString());
        certificate.setStatus(CertificateStatus.ACTIVE);
        return certificate;
    }

    /**
     * Generates Certificate model from the certificate file.
     * 
     * @param filename
     *            name of the certificate file.
     * @return Certificate model formed from the file.
     * @throws IOException
     * @throws CertificateException
     */
    public Certificate getCertificate(final String filename) throws IOException, CertificateException {
        final X509Certificate x509Certificate = getX509Certificate(filename);
        final Certificate certificate = toCertificate(x509Certificate);
        return certificate;
    }

    /**
     * Generates X509Certificate object from the certificate file.
     * 
     * @param filename
     *            name of the certificate file.
     * @return X509Certifcate object from certificate file.
     * @throws IOException
     * @throws CertificateException
     * @throws java.security.cert.CertificateException
     */
    public X509Certificate getX509Certificate(final String filename) throws IOException, CertificateException {
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(filename);
        final CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
        return (X509Certificate) certificateFactory.generateCertificate(inputStream);
    }

    /**
     * Prepares CertificateAurthority object from the given inputs.
     * 
     * @param caName
     *            name of the CA to be prepared.
     * @param subject
     *            subject object to be mapped to CA.
     * @param isRootCA
     *            flag representing Root CA or not.
     * @return CertificateAuthority prepared from the given inputs.
     */
    public CertificateAuthority getCertificateAuthority(final String caName, final Subject subject, final boolean isRootCA) {
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName(caName);
        certificateAuthority.setRootCA(isRootCA);
        certificateAuthority.setSubject(subject);
        return certificateAuthority;
    }

    /**
     * Generated dummy CertificateData entity.
     * 
     * @param notBefore
     *            notBefore for the certificate.
     * @param notAfter
     *            notAfter for the certificate.
     * @param issuedTime
     *            issuedTime of the certificate.
     * @param serialNumber
     *            serial number of the certificate.
     * @return CertificateData entity prepared from the certificate.
     * @throws IOException
     * @throws CertificateException
     * @throws CertificateEncodingException
     */
    public CertificateData createCertificateData(final String filePath, final Date notBefore, final Date notAfter, final Date issuedTime, final String serialNumber)
            throws CertificateEncodingException, CertificateException, IOException {
        final CertificateData certificateData = new CertificateData();
        certificateData.setId(1);
        certificateData.setNotBefore(notBefore);
        certificateData.setNotAfter(notAfter);
        certificateData.setIssuedTime(issuedTime);
        certificateData.setSerialNumber(serialNumber);
        certificateData.setStatus(CertificateStatus.ACTIVE.getId());
        certificateData.setCertificate(getX509Certificate(filePath).getEncoded());
        return certificateData;

    }

    /**
     * Generated dummy CertificateData entity.
     * 
     * @param serialNumber
     *            serial number of the certificate.
     * @return CertificateData entity prepared from the certificate.
     * @throws IOException
     * @throws CertificateException
     * @throws CertificateEncodingException
     */
    public CertificateData createCertificateData(final String filePath, final String serialNumber) throws CertificateEncodingException, CertificateException, IOException {
        return createCertificateData(filePath, new Date(), new Date(), new Date(), serialNumber);
    }

    public List<CertificateData> getCertificateDatas(final EntityType entityType) throws CertificateEncodingException, CertificateException, IOException {

        final List<CertificateData> certificateDatas = new ArrayList<CertificateData>();

        final CertificateData rootCertificateData = createCertificateData("certificates/RootCA.crt", "‎48 06 83 17 ee b7 7a a9");
        final CertificateData subCACertificateData = createCertificateData("certificates/SubCA.crt", "‎65 35 d8 7e b0 f1 63 8a");

        if (entityType.equals(EntityType.ENTITY)) {
            final CertificateData entityCertificateData = createCertificateData("certificates/Entity.crt", "‎1f 31 20 7e d9 8f fe 3a");
            entityCertificateData.setIssuerCertificate(subCACertificateData);
            certificateDatas.add(entityCertificateData);
        }

        subCACertificateData.setIssuerCertificate(rootCertificateData);
        certificateDatas.add(subCACertificateData);

        certificateDatas.add(rootCertificateData);

        return certificateDatas;

    }

    /**
     * get the entity active certificate.
     * 
     * @param caEntityName
     *            CAEntity name.
     * @return certificate Entity Active Certificate.
     * @throws IOException
     * @throws CertificateException
     */
    public Certificate getEntityCertificate() throws IOException, CertificateException {

        final Certificate entity_certificate = getCertificate("certificates/Entity.crt");
        entity_certificate.setStatus(CertificateStatus.ACTIVE);
        final Subject subject = subjectData.getSubject();
        final CertificateAuthority issuerCA = getCertificateAuthority(SUB_CA_NAME, subject, false);
        issuerCA.setIssuer(getCertificateAuthority(ROOT_CA_NAME, subject, true));
        entity_certificate.setIssuer(issuerCA);
        entity_certificate.setIssuerCertificate(getCAEntityCertificate());
        return entity_certificate;
    }

    /**
     * get the CAEntity active certificate.
     * 
     * @param caEntityName
     *            CAEntity Name.
     * @return Certificate CAEntity active certificate.
     * 
     * @throws IOException
     * @throws CertificateException
     */
    public Certificate getCAEntityCertificate() throws IOException, CertificateException {

        final Certificate caEntitycertificate = getCertificate("certificates/SubCA.crt");
        caEntitycertificate.setStatus(CertificateStatus.ACTIVE);
        final Subject subject = subjectData.getSubject();
        final CertificateAuthority issuerCA = getCertificateAuthority(ROOT_CA_NAME, subject, true);
        caEntitycertificate.setIssuer(issuerCA);
        caEntitycertificate.setIssuerCertificate(getRootCACertificate());
        return caEntitycertificate;
    }

    /**
     * get the RootCAEntity active certificate.
     * 
     * @return Certificate RootCA Active Certificate
     * 
     * @throws CertificateException
     * @throws IOException
     */
    public Certificate getRootCACertificate() throws CertificateException, IOException {
        final Certificate rootCACertificate = getCertificate("certificates/RootCA.crt");
        rootCACertificate.setStatus(CertificateStatus.ACTIVE);
        return rootCACertificate;

    }

    /**
     * get certificate chain from entity certificate to rootCA certificate.
     * 
     * @return List<Certificate>
     * @throws IOException
     * @throws CertificateException
     */
    public CertificateChain getEntityCertificateChain(CertificateStatus certificateStatus) throws CertificateException, IOException {

        final CertificateChain certificateChain = new CertificateChain();
        final List<Certificate> certificates = new ArrayList<Certificate>();

        Certificate entityCertificate = getEntityCertificate();

        if (certificateStatus.equals(CertificateStatus.ACTIVE)) {
            certificates.add(entityCertificate);
        } else {
            entityCertificate.setStatus(CertificateStatus.INACTIVE);
            certificates.add(entityCertificate);
        }

        final Certificate caEntityActiveCertificate = getCAEntityCertificate();
        certificates.add(caEntityActiveCertificate);

        final Certificate rootCAActiveCertificate = getRootCACertificate();
        certificates.add(rootCAActiveCertificate);

        certificateChain.setCertificateChain(certificates);
        return certificateChain;
    }

    /**
     * get certificate chain from CA certificate to rootCA certificate.
     * 
     * @return List<Certificate>
     * @throws IOException
     * @throws CertificateException
     */

    public CertificateChain getCAEntityCertificateChain(CertificateStatus certificateStatus) throws CertificateException, IOException {

        final CertificateChain certificateChain = new CertificateChain();
        final List<Certificate> certificates = new ArrayList<Certificate>();

        final Certificate caEntityCertificate = getCAEntityCertificate();

        if (certificateStatus.equals(CertificateStatus.ACTIVE)) {
            certificates.add(caEntityCertificate);
        } else {
            caEntityCertificate.setStatus(CertificateStatus.INACTIVE);
            certificates.add(caEntityCertificate);
        }

        final Certificate RootCACertificate = getRootCACertificate();
        certificates.add(RootCACertificate);

        certificateChain.setCertificateChain(certificates);
        return certificateChain;
    }

}
