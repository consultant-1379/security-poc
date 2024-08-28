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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.KeyStoreFileDTO;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

@RunWith(MockitoJUnitRunner.class)
public class EntityListResourceHelperTest {

    @InjectMocks
    EntityCertificateOperationsHelper entityCertificateOperationsHelper;

    @Mock
    Logger logger;

    @Mock
    PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Mock
    EntityCertificateManagementService entityCertificateManagementService;

    private static SetUPData setUPData;

    @Before
    public void setup() {

        setUPData = new SetUPData();

    }

    @Test
    public void testGetCertificateChain() throws CertificateException, IOException {

        final KeyStoreFileDTO keyStoreFileDTO = setUPData.getKeyStoreFileDTO();
        final Certificate certificate = setUPData.getEntityCertificate("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer");

        final List<Certificate> certificates = setUPData.getEntityCertificateChain("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer");
        final CertificateChain certificateChain = new CertificateChain();
        certificateChain.setCertificateChain(certificates);
        Mockito.when(pkiManagerEServiceProxy.getEntityCertificateManagementService()).thenReturn(entityCertificateManagementService);
        Mockito.when(entityCertificateManagementService.getCertificateChain(keyStoreFileDTO.getName())).thenReturn(certificateChain);

        final List<Certificate> actualCertificates = entityCertificateOperationsHelper.getEntityCertificateChain(keyStoreFileDTO.getName(), keyStoreFileDTO.isChain(), certificate);
        assertNotNull(actualCertificates);
        assertEquals(certificates.get(0), actualCertificates.get(0));

    }
}
