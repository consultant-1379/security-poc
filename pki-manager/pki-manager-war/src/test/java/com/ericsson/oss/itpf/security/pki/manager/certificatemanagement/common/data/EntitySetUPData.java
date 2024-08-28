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

import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.*;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

public class EntitySetUPData {

    private static SetUPData setUPData = new SetUPData();
    private static SubjectSetUPData subjectData = new SubjectSetUPData();

    /**
     * Prepares CertificatePrrofile with given inputs.
     * 
     * @return CertificateProfile object.
     * @throws DatatypeConfigurationException
     */
    public CertificateProfile getCertificateProfile() throws DatatypeConfigurationException {
        final CertificateProfile certificateProfile = new CertificateProfile();

        final DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
        final Duration certificateValidity = datatypeFactory.newDuration("P2Y2M2D");
        final Duration skewCertificateTime = datatypeFactory.newDuration("PT30M");

        certificateProfile.setVersion(CertificateVersion.V3);
        certificateProfile.setCertificateValidity(certificateValidity);
        certificateProfile.setIssuerUniqueIdentifier(false);
        certificateProfile.setSubjectUniqueIdentifier(false);
        certificateProfile.setSkewCertificateTime(skewCertificateTime);

        certificateProfile.setSignatureAlgorithm(setUPData.getSignatureAlgorithm("sha1withrsa"));

        final List<Algorithm> keyGenerationAlgorithmList = new ArrayList<Algorithm>();
        final Algorithm keyGenerationAlgorithm = setUPData.getKeyGenerationAlgorithm("RSA");
        keyGenerationAlgorithmList.add(keyGenerationAlgorithm);
        certificateProfile.setKeyGenerationAlgorithms(keyGenerationAlgorithmList);

        return certificateProfile;
    }

    public CertificateExtensions getCertificateExtensions() throws DatatypeConfigurationException {

        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        final List<CertificateExtension> certificateExtensionList = new ArrayList<CertificateExtension>();

        final SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier();
        subjectKeyIdentifier.setCritical(true);
        subjectKeyIdentifier.setKeyIdentifier(new KeyIdentifier());
        certificateExtensionList.add(subjectKeyIdentifier);

        final AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
        authorityKeyIdentifier.setCritical(true);
        certificateExtensionList.add(authorityKeyIdentifier);

        final AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess();
        certificateExtensionList.add(authorityInformationAccess);

        final CRLDistributionPoints cRLDistributionPoints = new CRLDistributionPoints();
        certificateExtensionList.add(cRLDistributionPoints);

        final SubjectAltName subjectAltName = new SubjectAltName();
        certificateExtensionList.add(subjectAltName);

        certificateExtensions.setCertificateExtensions(certificateExtensionList);

        return certificateExtensions;
    }

    public EntityProfile getEntityProfile() {

        final EntityProfile entityProfile = new EntityProfile();

        final KeyUsage keyUsageExtension = new KeyUsage();
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsageTypes.add(KeyUsageType.CRL_SIGN);
        keyUsageExtension.setCritical(true);
        keyUsageExtension.setSupportedKeyUsageTypes(keyUsageTypes);
        entityProfile.setKeyUsageExtension(keyUsageExtension);

        final ExtendedKeyUsage extendedKeyUsageExtension = new ExtendedKeyUsage();
        final List<KeyPurposeId> supportedKeyPurposeIds = new ArrayList<KeyPurposeId>();
        supportedKeyPurposeIds.add(KeyPurposeId.ID_KP_CLIENT_AUTH);
        extendedKeyUsageExtension.setSupportedKeyPurposeIds(supportedKeyPurposeIds);
        entityProfile.setExtendedKeyUsageExtension(extendedKeyUsageExtension);

        return entityProfile;
    }

    public BasicConstraints getBasicConstraints(final int pathlength) {

        final BasicConstraints basicConstraints = new BasicConstraints();
        basicConstraints.setIsCA(true);
        basicConstraints.setPathLenConstraint(pathlength);
        basicConstraints.setCritical(true);
        return basicConstraints;
    }

    public CAEntity getRootCAEntity() throws DatatypeConfigurationException {

        final Subject subject = subjectData.getSubject(SetUPData.ROOT_CA_NAME);
        final CAEntity rootCAEntity = setUPData.getCAEntity(SetUPData.ROOT_CA_NAME, subject, true);

        final CertificateProfile certificateProfile = getCertificateProfile();
        certificateProfile.setCertificateExtensions(getCertificateExtensions());

        certificateProfile.setIssuer(null);

        final BasicConstraints basicConstraints = getBasicConstraints(1);
        certificateProfile.getCertificateExtensions().getCertificateExtensions().add(basicConstraints);

        final List<CertificateProfile> certificateProfiles = new ArrayList<CertificateProfile>();
        certificateProfiles.add(certificateProfile);
        rootCAEntity.setCertificateProfiles(certificateProfiles);

        final EntityProfile entityProfile = getEntityProfile();
        entityProfile.setCertificateProfile(certificateProfile);
        rootCAEntity.setEntityProfile(entityProfile);

        return rootCAEntity;
    }

    public CAEntity getCAEntity() throws DatatypeConfigurationException {

        final Subject subject = subjectData.getSubject(SetUPData.SUB_CA_NAME);
        final CAEntity subCAEntity = setUPData.getCAEntity(SetUPData.SUB_CA_NAME, subject, false);

        final CertificateProfile certificateProfile = getCertificateProfile();
        certificateProfile.setCertificateExtensions(getCertificateExtensions());

        final Subject rootCA_subject = subjectData.getSubject(SetUPData.ROOT_CA_NAME);
        certificateProfile.setIssuer(setUPData.getCAEntity(SetUPData.ROOT_CA_NAME, rootCA_subject, true));

        final BasicConstraints basicConstraints = getBasicConstraints(2);
        certificateProfile.getCertificateExtensions().getCertificateExtensions().add(basicConstraints);

        final List<CertificateProfile> certificateProfiles = new ArrayList<CertificateProfile>();
        certificateProfiles.add(certificateProfile);
        subCAEntity.setCertificateProfiles(certificateProfiles);

        final EntityProfile entityProfile = getEntityProfile();
        entityProfile.setCertificateProfile(certificateProfile);
        subCAEntity.setEntityProfile(entityProfile);

        return subCAEntity;
    }

    public Entity getEntity() throws DatatypeConfigurationException {

        final Entity entity = new Entity();
        final Subject subject = subjectData.getSubject("Test");

        final CertificateProfile certificateProfile = getCertificateProfile();
        certificateProfile.setCertificateExtensions(getCertificateExtensions());

        certificateProfile.setIssuer(setUPData.getCAEntity(SetUPData.SUB_CA_NAME, subject, true));

        final EntityProfile entityProfile = getEntityProfile();
        entityProfile.setCertificateProfile(certificateProfile);
        entity.setEntityProfile(entityProfile);

        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(SetUPData.ENTITY_NAME);

        entityInfo.setSubject(subject);
        entity.setEntityInfo(entityInfo);
        return entity;
    }

}
