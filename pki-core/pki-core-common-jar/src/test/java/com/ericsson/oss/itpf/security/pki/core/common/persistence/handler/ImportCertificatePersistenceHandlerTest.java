/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.core.common.persistence.handler;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.Query;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;

@RunWith(MockitoJUnitRunner.class)
public class ImportCertificatePersistenceHandlerTest {

    @InjectMocks
    ImportCertificatePersistenceHandler importCertificatePersistenceHandler;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    EntityManager entityManager;

    @Mock
    Query query;

    @Mock
    List list;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    CertificateAuthorityData certificateAuthorityData;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;
    private static final String getLatestCertGenInfoOfCAQuery = "select cgf from CertificateGenerationInfoData cgf where  cgf.forExternalCA = true and cgf.cAEntityInfo in ( select ec.id from CertificateAuthorityData ec where ec.name = :name) ORDER BY cgf.id DESC";

    @Test
    public void testImportCertificateForRootCA() {
        String caName = "caName";
        Mockito.when(certificatePersistenceHelper.getCA(caName)).thenReturn(certificateAuthorityData);
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(persistenceManager.getEntityManager().createQuery(getLatestCertGenInfoOfCAQuery)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(list);
        importCertificatePersistenceHandler.importCertificateForRootCA(caName, x509Certificate);
        Mockito.verify(certificatePersistenceHelper).getCA(caName);
    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException.class)
    public void testCertificateServiceException() {
        String caEntityName = "caEntityName";
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        Mockito.when(persistenceManager.getEntityManager().createQuery(getLatestCertGenInfoOfCAQuery)).thenReturn(query);
        importCertificatePersistenceHandler.getLatestCertificateGenerationInfo(caEntityName);
    }

}
