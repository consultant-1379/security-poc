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
package com.ericsson.oss.itpf.security.pki.manager.common.setupdata;

import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;

/**
 * This class acts as builder for {@link CertificateProfileSetUpData}
 */
public class CertificateProfileSetUpData {

    private static final String EQUAL_VALIDITY = "PT1H1M30S";
    private static final String NOT_EQUAL_VALIDITY = "PT1H1M40S";
    private static final String EQUAL_SKEW_TIME = "PT1H1M31S";
    private static final String NOT_EQUAL_SKEW_TIME = "PT1H1M41S";
    private static final String EQUAL_PROFILE_NAME = "EqualCP";
    private static final String NOT_EQUAL_PROFILE_NAME = "NotEqualCP";
    private static final String EQUAL_ALGORITHM_NAME = "SHA256";
    private static final String NOT_EQUAL_ALGORITHM_NAME = "SHA256WithRSA";

    /**
     * Method that returns valid CertificateProfile
     * 
     * @return CertificateProfile
     * @throws DatatypeConfigurationException
     */
    public CertificateProfile getCertificateProfileForEqual() throws DatatypeConfigurationException {
        final CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setActive(true);
        certificateProfile.setCertificateExtensions(getCertificateExtensionsForEqual());
        certificateProfile.setCertificateValidity(DatatypeFactory.newInstance().newDuration(EQUAL_VALIDITY));
        certificateProfile.setForCAEntity(true);
        certificateProfile.setIssuer(new CAEntitySetUpData().getCAEntityForEqual());
        certificateProfile.setIssuer(new CAEntity());
        certificateProfile.setIssuerUniqueIdentifier(true);
        final List<Algorithm> keygenerationAlgorithms = new ArrayList<Algorithm>();
        keygenerationAlgorithms.add(new KeyGenerationAlgorithmSetUpData().getAlgorithmForEqual());
        certificateProfile.setKeyGenerationAlgorithms(keygenerationAlgorithms);
        certificateProfile.setName(EQUAL_PROFILE_NAME);
        final Algorithm signatureAlgorithm = new KeyGenerationAlgorithmSetUpData().getAlgorithmForEqual();
        signatureAlgorithm.setName(EQUAL_ALGORITHM_NAME);
        signatureAlgorithm.setKeySize(null);
        signatureAlgorithm.setType(AlgorithmType.SIGNATURE_ALGORITHM);
        certificateProfile.setSignatureAlgorithm(signatureAlgorithm);
        certificateProfile.setSkewCertificateTime(DatatypeFactory.newInstance().newDuration(EQUAL_SKEW_TIME));
        certificateProfile.setSubjectUniqueIdentifier(true);
        certificateProfile.setType(ProfileType.CERTIFICATE_PROFILE);
        certificateProfile.setVersion(CertificateVersion.V3);
        return certificateProfile;
    }

    /**
     * Method that returns different valid CertificateProfile
     * 
     * @return CertificateProfile
     * @throws DatatypeConfigurationException
     */
    public CertificateProfile getCertificateProfileForNotEqual() throws DatatypeConfigurationException {
        final CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setActive(false);
        certificateProfile.setCertificateExtensions(getCertificateExtensionsForNotEqual());
        certificateProfile.setCertificateValidity(DatatypeFactory.newInstance().newDuration(NOT_EQUAL_VALIDITY));
        certificateProfile.setForCAEntity(false);
        certificateProfile.setIssuer(new CAEntitySetUpData().getCAEntityForNotEqual());
        certificateProfile.setIssuerUniqueIdentifier(false);
        final List<Algorithm> keygenerationAlgorithms = new ArrayList<Algorithm>();
        keygenerationAlgorithms.add(new KeyGenerationAlgorithmSetUpData().getAlgorithmForNotEqual());
        certificateProfile.setKeyGenerationAlgorithms(keygenerationAlgorithms);
        certificateProfile.setName(NOT_EQUAL_PROFILE_NAME);
        final Algorithm signatureAlgorithm = new KeyGenerationAlgorithmSetUpData().getAlgorithmForNotEqual();
        signatureAlgorithm.setName(NOT_EQUAL_ALGORITHM_NAME);
        signatureAlgorithm.setKeySize(null);
        signatureAlgorithm.setType(AlgorithmType.SIGNATURE_ALGORITHM);
        certificateProfile.setSignatureAlgorithm(signatureAlgorithm);
        certificateProfile.setSkewCertificateTime(DatatypeFactory.newInstance().newDuration(NOT_EQUAL_SKEW_TIME));
        certificateProfile.setSubjectUniqueIdentifier(false);
        certificateProfile.setType(ProfileType.CERTIFICATE_PROFILE);
        certificateProfile.setVersion(CertificateVersion.V3);
        return certificateProfile;
    }

    /**
     * 
     * Method that returns valid CertificateExtensions
     * 
     * @return CertificateExtensions
     * 
     */
    public CertificateExtensions getCertificateExtensionsForEqual() {
        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        final List<CertificateExtension> extensionsList = new ArrayList<CertificateExtension>();
        extensionsList.add(new BasicConstraintsSetUpData().getBasicConstraintsForEqual());
        extensionsList.add(new AuthorityInformationAccessSetUpData().getAuthorityInformationAccessForEqual());
        extensionsList.add(new AuthorityKeyIdentifierSetUpData().getAuthorityKeyIdentifierForEqual());
        extensionsList.add(new SubjectKeyIdentifierSetUpData().getSubjectKeyIdentifierForEqual());
        extensionsList.add(new KeyUsageSetUpData().getKeyUsageForEqual());
        extensionsList.add(new ExtendedKeyUsageSetUpData().getExtendedKeyUsageForEqual());
        final List<DistributionPoint> crlDistributionPointList = new ArrayList<DistributionPoint>();
        crlDistributionPointList.add((DistributionPoint) new CRLDistributionPointSetUpData().getCRLDistributionPointForEqual());
        final CRLDistributionPoints crlDistributionPoints = new CRLDistributionPoints();
        crlDistributionPoints.setDistributionPoints(crlDistributionPointList);
        extensionsList.add(crlDistributionPoints);
        certificateExtensions.setCertificateExtensions(extensionsList);
        return certificateExtensions;
    }

    /**
     * Method that returns valid CertificateExtensions
     * 
     * @return CertificateExtensions
     * 
     */
    public CertificateExtensions getCertificateExtensionsForNotEqual() {
        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        final List<CertificateExtension> extensionsList = new ArrayList<CertificateExtension>();
        extensionsList.add(new BasicConstraintsSetUpData().getBasicConstraintsForNotEqual());
        extensionsList.add(new AuthorityInformationAccessSetUpData().getAuthorityInformationAccessForNotEqual());
        extensionsList.add(new AuthorityKeyIdentifierSetUpData().getAuthorityKeyIdentifierForNotEqual());
        extensionsList.add(new SubjectKeyIdentifierSetUpData().getSubjectKeyIdentifierForNotEqual());
        extensionsList.add(new KeyUsageSetUpData().getKeyUsageForNotEqual());
        extensionsList.add(new ExtendedKeyUsageSetUpData().getExtendedKeyUsageForNotEqual());
        final List<DistributionPoint> crlDistributionPointList = new ArrayList<DistributionPoint>();
        crlDistributionPointList.add((DistributionPoint) new CRLDistributionPointSetUpData().getCRLDistributionPointForNotEqual());
        final CRLDistributionPoints crlDistributionPoints = new CRLDistributionPoints();
        crlDistributionPoints.setDistributionPoints(crlDistributionPointList);
        extensionsList.add(crlDistributionPoints);
        certificateExtensions.setCertificateExtensions(extensionsList);
        return certificateExtensions;
    }

    /**
     * Method that returns valid CertificateProfile
     * 
     * @return CertificateProfile
     * @throws DatatypeConfigurationException
     */
    public CertificateProfile getCertificateProfileForEntityEqual() throws DatatypeConfigurationException {
        final CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setName(EQUAL_PROFILE_NAME);
        return certificateProfile;
    }

    /**
     * Method that returns different valid CertificateProfile
     * 
     * @return CertificateProfile
     * @throws DatatypeConfigurationException
     */
    public CertificateProfile getCertificateProfileForEntityNotEqual() throws DatatypeConfigurationException {
        final CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setName(NOT_EQUAL_PROFILE_NAME);
        return certificateProfile;
    }
}
