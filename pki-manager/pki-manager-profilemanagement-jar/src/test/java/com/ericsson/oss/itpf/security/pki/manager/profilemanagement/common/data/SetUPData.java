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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

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
    private static SubjectAltNameSetUPData subjectAltNameSetUPData = new SubjectAltNameSetUPData();

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
    public KeyPair generateKeyPair(final String keyPairAlgorithm, final int KeySize) throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        final KeyPairGenerator gen = KeyPairGenerator.getInstance(keyPairAlgorithm);
        gen.initialize(KeySize);
        return gen.generateKeyPair();
    }

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
     * @return
     * @throws IOException
     * @throws CertificateException
     * @throws java.security.cert.CertificateException
     */
    public Certificate createRootCertificate() throws IOException, CertificateException {

        final Certificate certificate = getCertificate("certificates/ENMRootCA.crt");

        final Subject subject = subjectData.getSubject("TCS", "PKI", "Ericsson");
        certificate.setSubject(subject);

        final SubjectAltName subjectAltName = subjectAltNameSetUPData.getSubjectAltName();
        certificate.setSubjectAltName(subjectAltName);

        return certificate;
    }

    /**
     * Create Certificate for SubCA
     * 
     * @return Certificate
     * @throws IOException
     * @throws CertificateException
     */
    public Certificate createSubCACertificate() throws IOException, CertificateException {

        final Certificate certificate = getCertificate("certificates/ENMRootCA.crt");

        final Subject subject = subjectData.getSubject("TCS", "PKI", "Ericsson");
        certificate.setSubject(subject);

        final SubjectAltName subjectAltName = subjectAltNameSetUPData.getSubjectAltName();
        certificate.setSubjectAltName(subjectAltName);

        final CertificateAuthority issuer = getCertificateAuthority(SetUPData.ROOT_CA_NAME, subject, true);
        certificate.setIssuer(issuer);

        return certificate;
    }

    /**
     * Prepares Entity object.
     * 
     * @param entityName
     *            name of the entity to be prepared.
     * @param subject
     *            subject object to be mapped to entity.
     * @return Entity object prepared from given input.
     */
    public Entity getEntity(final Subject subject, final SubjectAltName subjectAltName) {
        final Entity entity = new Entity();

        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(SetUPData.ENTITY_NAME);
        entityInfo.setSubject(subject);
        entityInfo.setSubjectAltName(subjectAltName);
        entity.setEntityInfo(entityInfo);

        final EntityProfile entityProfile = new EntityProfile();

        final CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setIssuer(getCAEntity(ENTITY_NAME, subject, true));
        entityProfile.setCertificateProfile(certificateProfile);
        entity.setEntityProfile(entityProfile);

        return entity;
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

    public CertificateAuthority getSubjectAltNameCertificateAuthority(final String caEntityName, final SubjectAltName subjectAltName, final boolean isRootCA) {
        final CertificateAuthority SubjectAltNameCertificateAuthority = new CertificateAuthority();
        SubjectAltNameCertificateAuthority.setSubjectAltName(subjectAltName);
        return SubjectAltNameCertificateAuthority;
    }

    /**
     * Prepares CAEntity object from the given inputs.
     * 
     * @param caEntityName
     *            name of the CA entity.
     * @param subject
     *            subject object to be mapped to CA.
     * @param isRootCA
     *            flag representing Root CA or not.
     * @return CAEntity prepared with given inputs.
     */
    public CAEntity getCAEntity(final String caEntityName, final Subject subject, final boolean isRootCA) {

        final CAEntity caEntity = new CAEntity();
        caEntity.setCertificateAuthority(getCertificateAuthority(caEntityName, subject, isRootCA));
        caEntity.setKeyGenerationAlgorithm(new Algorithm());
        final EntityProfile entityProfile = new EntityProfile();
        final CertificateProfile certificateProfile = new CertificateProfile();
        entityProfile.setCertificateProfile(certificateProfile);
        caEntity.setEntityProfile(entityProfile);
        return caEntity;
    }

    public CAEntity getCAEntity(final String caEntityName, final SubjectAltName subjectAltName, final boolean isRootCA) {

        final CAEntity caEntity = new CAEntity();
        caEntity.setCertificateAuthority(getSubjectAltNameCertificateAuthority(caEntityName, subjectAltName, isRootCA));
        caEntity.setKeyGenerationAlgorithm(new Algorithm());
        final EntityProfile entityProfile = new EntityProfile();
        final CertificateProfile certificateProfile = new CertificateProfile();
        entityProfile.setCertificateProfile(certificateProfile);
        caEntity.setEntityProfile(entityProfile);
        return caEntity;
    }

    public Certificate toCertificate(final CertificateData certificateData) {
        final Certificate certificate = new Certificate();
        certificate.setId(certificateData.getId());
        certificate.setNotBefore(certificateData.getNotBefore());
        certificate.setNotAfter(certificateData.getNotAfter());
        certificate.setIssuedTime(certificateData.getIssuedTime());
        certificate.setSerialNumber(certificateData.getSerialNumber());
        certificate.setStatus(CertificateStatus.getStatus(certificateData.getStatus()));
        return certificate;
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
    public CertificateData createCertificateData(final Date notBefore, final Date notAfter, final Date issuedTime, final String serialNumber) throws CertificateEncodingException,
            CertificateException, IOException {
        final CertificateData certificateData = new CertificateData();
        certificateData.setId(1);
        certificateData.setNotBefore(notBefore);
        certificateData.setNotAfter(notAfter);
        certificateData.setIssuedTime(issuedTime);
        certificateData.setSerialNumber(serialNumber);
        certificateData.setStatus(CertificateStatus.ACTIVE.getId());
        certificateData.setCertificate(getX509Certificate("certificates/Entity.crt").getEncoded());
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
    public CertificateData createCertificateData(final String serialNumber) throws CertificateEncodingException, CertificateException, IOException {
        return createCertificateData(new Date(), new Date(), new Date(), serialNumber);
    }

    /**
     * Create entity Data.
     * 
     * @param entityName
     * @return EntityData
     * @throws IOException
     * @throws CertificateException
     * @throws CertificateEncodingException
     */
    public EntityData createEntityData(final String entityName) throws CertificateEncodingException, CertificateException, IOException {

        final EntityData entityData = new EntityData();
        entityData.setId(12345);
        final EntityInfoData entityInfoData = new EntityInfoData();
        entityInfoData.setName(entityName);
        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        certificateDatas.add(createCertificateData("12345"));
        entityInfoData.setCertificateDatas(certificateDatas);
        entityData.setEntityInfoData(entityInfoData);
        return entityData;
    }

    /**
     * create CAEntity Data.
     * 
     * @param caEntityName
     *            return CAEntityData
     */
    public CAEntityData createCAEntityData(final String caEntityName, final boolean isRootCA) {
        final CAEntityData caEntityData = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName(caEntityName);
        certificateAuthorityData.setRootCA(isRootCA);
        if (isRootCA) {
            certificateAuthorityData.setSubjectDN("CN=ENMSubCA");
        } else {
            certificateAuthorityData.setSubjectDN("CN=TestCA");
        }
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        caEntityData.setExternalCA(true);
        return caEntityData;
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

        final Certificate caEntitycertificate = getCertificate("certificates/ENMRootCA.crt");
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
        final Certificate rootCACertificate = getCertificate("certificates/ENMRootCA.crt");
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
    public List<CertificateChain> getEntityCertificateChain(final CertificateStatus certificateStatus) throws CertificateException, IOException {

        final List<CertificateChain> certificateChains = new ArrayList<CertificateChain>();
        final CertificateChain certificateChain = new CertificateChain();
        final List<Certificate> certificates = new ArrayList<Certificate>();

        final Certificate entityCertificate = getEntityCertificate();

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
        certificateChains.add(certificateChain);
        return certificateChains;
    }

    /**
     * get certificate chain from CA certificate to rootCA certificate.
     * 
     * @return List<Certificate>
     * @throws IOException
     * @throws CertificateException
     */

    public List<CertificateChain> getCAEntityCertificateChain(final CertificateStatus certificateStatus) throws CertificateException, IOException {

        final List<CertificateChain> certificateChains = new ArrayList<CertificateChain>();
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
        certificateChains.add(certificateChain);
        return certificateChains;
    }

    public Algorithm getSignatureAlgorithm(final String name) {

        final Algorithm signatureAlgorithm = new Algorithm();
        signatureAlgorithm.setName(name);
        signatureAlgorithm.setSupported(true);
        signatureAlgorithm.setType(AlgorithmType.SIGNATURE_ALGORITHM);
        return signatureAlgorithm;
    }

    public Algorithm getKeyGenerationAlgorithm(final String name) {

        final Algorithm keyGenerationAlgorithm = new Algorithm();
        keyGenerationAlgorithm.setName(name);
        keyGenerationAlgorithm.setKeySize(2048);
        keyGenerationAlgorithm.setSupported(true);
        keyGenerationAlgorithm.setType(AlgorithmType.MESSAGE_DIGEST_ALGORITHM);
        return keyGenerationAlgorithm;
    }

    public AlgorithmData getAlgorithmData(final Algorithm algorithm) {

        final AlgorithmData algorithmData = new AlgorithmData();
        algorithmData.setName(algorithm.getName());
        algorithmData.setKeySize(algorithm.getKeySize());
        algorithmData.setType(algorithm.getType().getId());
        return algorithmData;

    }

    /**
     * Generates ExternalCRLInfo model from the crl file.
     * 
     * @param filename
     *            name of the crl file.
     * @return ExternalCRLInfo model formed from the file.
     * @throws IOException
     * @throws CertificateException
     */
    public ExternalCRLInfo getExternalCRLInfo(final String filename) throws IOException, CertificateException {
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(filename);
        final CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
        try {
            final X509CRL x509CRL = (X509CRL) certificateFactory.generateCRL(inputStream);
            return fillExternalCRLInfo(x509CRL);
        } catch (final CRLException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * @param x509CRL
     * @return
     * @throws IOException
     * @throws CRLException
     */
    private ExternalCRLInfo fillExternalCRLInfo(final X509CRL x509CRL) throws CRLException, IOException {
        final ExternalCRLInfo crl = new ExternalCRLInfo();
        crl.setAutoUpdate(true);
        crl.setAutoUpdateCheckTimer(7);
        crl.setNextUpdate(new Date());
        crl.setUpdateURL("updateURL");
        crl.setX509CRL(new X509CRLHolder(x509CRL.getEncoded()));
        return crl;
    }

}
