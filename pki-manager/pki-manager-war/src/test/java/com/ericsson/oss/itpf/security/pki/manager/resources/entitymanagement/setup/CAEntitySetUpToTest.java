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
package com.ericsson.oss.itpf.security.pki.manager.resources.entitymanagement.setup;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.setup.EntityProfileSetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.setup.AlgorithmSetUpToTest;

/**
 * Class for Test Data creation for {@link CAEntity}
 * 
 * @version 1.2.4
 */
public class CAEntitySetUpToTest {

    private CAEntity caEntity;

    /**
     * Method to provide dummy data for tests.
     */
    public CAEntitySetUpToTest() {
        fillCAEntity();
    }

    /**
     * Method that returns CAEntity object for tests.
     */
    public CAEntity getCAEntity() {
        return caEntity;
    }

    private void fillCAEntity() {
        caEntity = new CAEntity();

        caEntity.setCertificateAuthority(createCertificateAuthority());
        caEntity.setEntityProfile(new EntityProfileSetUpToTest().getEntityProfile());
        caEntity.setKeyGenerationAlgorithm(new AlgorithmSetUpToTest().getKeyGenerationAlgorithmList().get(0));
        caEntity.setPublishCertificatetoTDPS(true);
        caEntity.setType(EntityType.CA_ENTITY);
    }

    private CertificateAuthority createCertificateAuthority() {
        final CertificateAuthority certificateAuthority = new CertificateAuthority();

        certificateAuthority.setId(1);
        certificateAuthority.setName("rest_ca_entity");
        certificateAuthority.setRootCA(true);
        certificateAuthority.setStatus(CAStatus.ACTIVE);
        certificateAuthority.setSubject(new SubjectSetUpToTest().getSubject());
        certificateAuthority.setSubjectAltName(new SubjectAltNameSetUpToTest().getSubjectAltName());

        return certificateAuthority;
    }
}
