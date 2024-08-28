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
import java.security.cert.CertificateException;
import java.util.*;

import javax.xml.datatype.*;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.common.util.DateUtility;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

public class EntitySetUPData {

    private static SetUPData setUPData = new SetUPData();
    private static SubjectSetUPData subjectData = new SubjectSetUPData();
    private static SubjectAltNameSetUPData subjectAltNameSetUPData = new SubjectAltNameSetUPData();
    public Date entityDate = null;

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
        entityDate = DateUtility.addDurationToDate(new Date(), certificateValidity);
        final Duration skewCertificateTime = datatypeFactory.newDuration("PT30M");

        certificateProfile.setVersion(CertificateVersion.V3);
        certificateProfile.setCertificateValidity(certificateValidity);
        certificateProfile.setIssuerUniqueIdentifier(false);
        certificateProfile.setSubjectUniqueIdentifier(false);
        certificateProfile.setSkewCertificateTime(skewCertificateTime);

        certificateProfile.setSignatureAlgorithm(setUPData.getSignatureAlgorithm("SHA1withRSA"));

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
    
    public CRLDistributionPoints getCRLDistributionPoints(final boolean ipv4Enabled, final boolean ipv6Enabled, final boolean dnsEnabled) {
        
        CRLDistributionPoints crlDistPointsRet = new CRLDistributionPoints();
        if(ipv4Enabled) {
            DistributionPoint crlDistPointIPv4 = new DistributionPoint();
            DistributionPointName distPointNameIPv4 = new DistributionPointName();
            List<String> ipv4FullNamesList = new ArrayList<String>();
            ipv4FullNamesList.add("http://$FQDN_IPV4/pki-cdps?ca_name=$CANAME&amp;ca_cert_serialnumber=$CACERTSERIALNUMBER");
            distPointNameIPv4.setFullName(ipv4FullNamesList);
            crlDistPointIPv4.setDistributionPointName(distPointNameIPv4);
            crlDistPointsRet.getDistributionPoints().add(crlDistPointIPv4);
        }
        if(ipv6Enabled) {
            DistributionPoint crlDistPointIPv6 = new DistributionPoint();
            DistributionPointName distPointNameIPv6 = new DistributionPointName();
            List<String> ipv6FullNamesList = new ArrayList<String>();
            ipv6FullNamesList.add("http://$FQDN_IPV6/pki-cdps?ca_name=$CANAME&amp;ca_cert_serialnumber=$CACERTSERIALNUMBER");
            distPointNameIPv6.setFullName(ipv6FullNamesList);
            crlDistPointIPv6.setDistributionPointName(distPointNameIPv6);
            crlDistPointsRet.getDistributionPoints().add(crlDistPointIPv6);
        }
        if(dnsEnabled) {
            DistributionPoint crlDistPointDNS = new DistributionPoint();
            DistributionPointName distPointNameDNS = new DistributionPointName();
            List<String> dnsFullNamesList = new ArrayList<String>();
            dnsFullNamesList.add("http://$FQDN_DNS/pki-cdps?ca_name=$CANAME&amp;ca_cert_serialnumber=$CACERTSERIALNUMBER");
            distPointNameDNS.setFullName(dnsFullNamesList);
            crlDistPointDNS.setDistributionPointName(distPointNameDNS);
            crlDistPointsRet.getDistributionPoints().add(crlDistPointDNS);
        }
        return crlDistPointsRet;
    };

    public CAEntity getRootCAEntity() throws DatatypeConfigurationException, CertificateException, IOException {

        final Subject subject = subjectData.getSubject(SetUPData.ROOT_CA_NAME);
        final SubjectAltName subjectAltName = subjectAltNameSetUPData.getSANForEntity();

        final CAEntity rootCAEntity = setUPData.getCAEntity(SetUPData.ROOT_CA_NAME, subject, true);
        rootCAEntity.getCertificateAuthority().setSubjectAltName(subjectAltName);

        rootCAEntity.getCertificateAuthority().setActiveCertificate(setUPData.getRootCACertificate());
        
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

    public CAEntity getCAEntity() throws DatatypeConfigurationException, CertificateException, IOException {

        final Subject subject = subjectData.getSubject(SetUPData.SUB_CA_NAME);
        final SubjectAltName subjectAltName = subjectAltNameSetUPData.getSANForEntity();

        final CAEntity subCAEntity = setUPData.getCAEntity(SetUPData.SUB_CA_NAME, subject, false);
        subCAEntity.getCertificateAuthority().setSubjectAltName(subjectAltName);

        final CertificateProfile certificateProfile = getCertificateProfile();
        certificateProfile.setCertificateExtensions(getCertificateExtensions());

        final Subject rootCA_subject = subjectData.getSubject(SetUPData.ROOT_CA_NAME);
        certificateProfile.setIssuer(setUPData.getCAEntity(SetUPData.ROOT_CA_NAME, rootCA_subject, true));
        certificateProfile.getIssuer().getCertificateAuthority().setActiveCertificate(setUPData.createRootCertificate());
        final BasicConstraints basicConstraints = getBasicConstraints(2);
        final CRLDistributionPoints crlDistributionPoints = getCRLDistributionPoints(true,true,true);
        certificateProfile.getCertificateExtensions().getCertificateExtensions().add(basicConstraints);
        certificateProfile.getCertificateExtensions().getCertificateExtensions().add(crlDistributionPoints);

        final List<CertificateProfile> certificateProfiles = new ArrayList<CertificateProfile>();
        certificateProfiles.add(certificateProfile);
        subCAEntity.setCertificateProfiles(certificateProfiles);

        final EntityProfile entityProfile = getEntityProfile();
        entityProfile.setCertificateProfile(certificateProfile);
        subCAEntity.setEntityProfile(entityProfile);

        return subCAEntity;
    }

    public Entity getEntity() throws DatatypeConfigurationException, CertificateException, IOException {

        final Entity entity = new Entity();
        final Subject subject = subjectData.getSubject("Test");
        final SubjectAltName subjectAltName = subjectAltNameSetUPData.getSANForEntity();

        final CertificateProfile certificateProfile = getCertificateProfile();
        certificateProfile.setCertificateExtensions(getCertificateExtensions());

        certificateProfile.setIssuer(setUPData.getCAEntity(SetUPData.SUB_CA_NAME, subject, true));
        certificateProfile.getIssuer().getCertificateAuthority().setActiveCertificate(setUPData.createSubCACertificate());
        final EntityProfile entityProfile = getEntityProfile();
        entityProfile.setCertificateProfile(certificateProfile);
        entity.setEntityProfile(entityProfile);

        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(SetUPData.ENTITY_NAME);
        entityInfo.setSubjectAltName(subjectAltName);
        entityInfo.setSubject(subject);
        entity.setEntityInfo(entityInfo);
        return entity;
    }

}
