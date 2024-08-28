/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.persistence.common.data;

import java.util.Set;

import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;


/**
 * This class populates dummy data for CA and End entities
 *
 * @author xnagcho
 * @version 1.1.30
 *
 */
public class CAEntityDataSetUp {

    /**
     * Method that returns CertificateAuthority with given name
     *
     * @param name
     *            name of the CAEntity
     * @param subject
     *            subject to be set in certificate authority object
     * @param subjectAltName
     *            subjectAltName to be set in certificate authority object
     * @return CertificateAuthority CertificateAuthority object with given name, subject and subject alt name.
     */
    private CertificateAuthorityData getCertificateAuthority(final String name, final boolean isRootCA, final String subject, final String subjectAltName) {
        final CertificateAuthorityData certificateAuthority = new CertificateAuthorityData();
        certificateAuthority.setName(name);
        certificateAuthority.setRootCA(isRootCA);

        return certificateAuthority;
    }

    /**
     * Method that returns CAEntity with given name
     *
     * @param name
     *            name of the CAEntity
     * @param entityProfileData
     *            {@link EntityProfileData} object to be set in {@link CAEntity}
     * @param certificateProfileDatas
     *            {@link CertificateProfileData} to be set
     * @param subject
     *            Subject to be set in {@link CAEntity}
     * @param subjectAltName
     *            SubejctAltName to be set in {@link CAEntity}
     * @return CAEntity instance of {@link CAEntity} with given values set.
     */
    public CAEntityData getCAEntity(final long id, final String name, final boolean isRootCA, final EntityProfileData entityProfileData, final Set<CertificateProfileData> certificateProfileDatas,
                                    final String subject, final String subjectAltName) {
        final AlgorithmDataSetUp algorithmDataSetUp = new AlgorithmDataSetUp();

        final CAEntityData caEntity = new CAEntityData();
        caEntity.setId(id);
        caEntity.setKeyGenerationAlgorithm(algorithmDataSetUp.getSupportedKeyGenerationAlgorithm());
        caEntity.setEntityProfileData(entityProfileData);
        caEntity.setCertificateAuthorityData(getCertificateAuthority(name, isRootCA, subject, subjectAltName));

        return caEntity;
    }
}
