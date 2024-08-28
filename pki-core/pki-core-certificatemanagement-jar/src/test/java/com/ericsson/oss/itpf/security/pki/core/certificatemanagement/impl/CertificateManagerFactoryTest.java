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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.impl;

import static org.junit.Assert.assertNotNull;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagerFactoryTest {

    @InjectMocks
    private CertificateManagerFactory certificateManagerFactory;

    @Mock
    CAEntityCertificateManager cAEntityCertificateManager;

    @Mock
    EntityCertificateManager entityCertificateManager;

    @Mock
    Logger logger;

    private CertificateGenerationInfo certificateGenerationInfo;
    private CertificateExtensions certificateExtensions;
    private List<CertificateExtension> certificateExtensionsList;
    private BasicConstraints basicConstraints;
    private CertificateAuthority certificateAuthority ;
    private EntityInfo entityInfo;

    /**
     * Prepares initial data.
     */
    @Before
    public void setUp() {

        certificateGenerationInfo = new CertificateGenerationInfo();
        certificateExtensions = new CertificateExtensions();
        certificateExtensionsList = new ArrayList<CertificateExtension>();
        basicConstraints = new BasicConstraints();
        certificateAuthority= new CertificateAuthority();
        entityInfo= new EntityInfo();
        certificateAuthority.setName("ENM_ROOT_CA");
        entityInfo.setName("ENM_CA");
        certificateGenerationInfo.setCAEntityInfo(certificateAuthority);
        certificateGenerationInfo.setEntityInfo(entityInfo);
    }

    /**
     * Method to test {@link CertificateManagerFactory} returns instance of {@link CAEntityCertificateManager} based on the {@link CertificateGenerationInfo}.
     */
    @Test
    public void testGetCAEntityManager() {

        setCAData();
        final CertificateManager manager = certificateManagerFactory.getManager(certificateGenerationInfo);

        assertNotNull(manager);
        certificateExtensionsList.clear();
    }

    /**
     * Method to test {@link CertificateManagerFactory} returns instance of {@link EntityCertificateManager} based on the {@link CertificateGenerationInfo}.
     */
    @Test
    public void testGetEntityManager() {

        setEntityData();
        final CertificateManager manager = certificateManagerFactory.getManager(certificateGenerationInfo);

        assertNotNull(manager);
        certificateExtensionsList.clear();
    }

    private void setCAData() {

        basicConstraints.setIsCA(true);
        certificateExtensionsList.add(basicConstraints);
        certificateExtensions.setCertificateExtensions(certificateExtensionsList);
        certificateGenerationInfo.setCertificateExtensions(certificateExtensions);
    }

    private void setEntityData() {

        basicConstraints = new BasicConstraints();
        basicConstraints.setIsCA(false);
        certificateExtensionsList.add(basicConstraints);
        certificateExtensionsList.add(basicConstraints);
        certificateExtensions.setCertificateExtensions(certificateExtensionsList);
        certificateGenerationInfo.setCertificateExtensions(certificateExtensions);
    }

}
