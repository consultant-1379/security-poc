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
package com.ericsson.oss.itpf.security.pki.manager.local.service.ejb;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.*;

import javax.persistence.PersistenceException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.tdps.TDPSPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;

@RunWith(MockitoJUnitRunner.class)
public class TrustDistributionLocalServiceBeanTest {

    @InjectMocks
    TrustDistributionLocalServiceBean trustDistributionLocalServiceBean;

    @Mock
    TDPSPersistenceHandler tDPSPersistenceHandler;

    @Test
    public void testGetPublishedCertificates() throws CertificateException, PersistenceException, IOException {

        Certificate entityCertificate = new Certificate();
        entityCertificate.setId(0);

        Certificate caCertificate = new Certificate();
        caCertificate.setId(0);

        Map<String, List<Certificate>> entityCertificateInfoMap = new HashMap<String, List<Certificate>>();
        Map<String, List<Certificate>> caCertificateInfoMap = new HashMap<String, List<Certificate>>();

        Mockito.when(tDPSPersistenceHandler.getPublishableCACertificates()).thenReturn(caCertificateInfoMap);
        Mockito.when(tDPSPersistenceHandler.getPublishableEntityCertificates()).thenReturn(entityCertificateInfoMap);

        trustDistributionLocalServiceBean.getPublishedCertificates(EntityType.CA_ENTITY);
        trustDistributionLocalServiceBean.getPublishedCertificates(EntityType.ENTITY);

        Mockito.verify(tDPSPersistenceHandler).getPublishableCACertificates();
        Mockito.verify(tDPSPersistenceHandler).getPublishableEntityCertificates();

    }

    @Test
    public void testUpdateCertificateStatus() throws CertificateException, PersistenceException, IOException {

        trustDistributionLocalServiceBean.updateCertificateStatus( EntityType.ENTITY, "NEW_ENTITY", "NEW_CA", "123456", false);

    }
}
