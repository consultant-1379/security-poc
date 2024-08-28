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
package com.ericsson.oss.itpf.security.pki.manager.test.setup;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.datatype.DatatypeConfigurationException;

import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;

public class CAEntitySetUpData {

    private Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetails = new HashSet<CertificateExpiryNotificationDetails>();

    /**
     * Method that returns valid CAEntity
     * 
     * @return CAEntity
     * @throws DatatypeConfigurationException
     */
    public CAEntity getCAEntityForEqual() throws DatatypeConfigurationException {
        final CAEntity caEntity = new CAEntity();
        final List<CertificateProfile> certificateProfiles = new ArrayList<CertificateProfile>();
        certificateProfiles.add(new CertificateProfileSetUpData().getCertificateProfileForEntityEqual());

        caEntity.setCertificateAuthority(new CertificateAuthoritySetUpData().build());
        caEntity.setEntityProfile(new EntityProfileSetUpData().getEntityProfileForEntityEqual());
        caEntity.setKeyGenerationAlgorithm(new KeyGenerationAlgorithmSetUpData().getAlgorithmForEqual());
        caEntity.setPublishCertificatetoTDPS(true);
        caEntity.setCertificateProfiles(certificateProfiles);
        caEntity.setType(EntityType.CA_ENTITY);
        caEntity.setSubjectUniqueIdentifierValue("nmsadm");
        caEntity.setCertificateExpiryNotificationDetails(certificateExpiryNotificationDetails);

        return caEntity;
    }

    /**
     * Method that returns valid CAEntity
     * 
     * @return CAEntity
     * @throws DatatypeConfigurationException
     */
    public CAEntity getCAEntityForNotEqual() throws DatatypeConfigurationException {
        final CAEntity caEntity = new CAEntity();
        final List<CertificateProfile> certificateProfiles = new ArrayList<CertificateProfile>();
        certificateProfiles.add(new CertificateProfileSetUpData().getCertificateProfileForEntityNotEqual());

        caEntity.setCertificateAuthority(new CertificateAuthoritySetUpData().build());
        caEntity.setEntityProfile(new EntityProfileSetUpData().getEntityProfileForEntityEqual());
        caEntity.setKeyGenerationAlgorithm(new KeyGenerationAlgorithmSetUpData().getAlgorithmForNotEqual());
        caEntity.setPublishCertificatetoTDPS(true);
        caEntity.setCertificateProfiles(certificateProfiles);
        caEntity.setType(EntityType.CA_ENTITY);
        caEntity.setSubjectUniqueIdentifierValue("nmsadm1");
        caEntity.setCertificateExpiryNotificationDetails(certificateExpiryNotificationDetails);
        return caEntity;
    }
}
