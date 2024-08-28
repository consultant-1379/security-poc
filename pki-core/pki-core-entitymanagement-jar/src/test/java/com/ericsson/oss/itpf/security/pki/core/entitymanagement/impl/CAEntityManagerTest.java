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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl;

import static org.mockito.Mockito.*;

import java.security.cert.CertificateException;

import javax.persistence.PersistenceException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateAuthorityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.common.utils.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.validators.CAValidator;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException;

@RunWith(MockitoJUnitRunner.class)
public class CAEntityManagerTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(CAEntityManager.class);

    @InjectMocks
    CAEntityManager cAEntityManager;

    @Mock
    CAEntityPersistenceHandler cAEntityPersistenceHandler;

    @Mock
    CAValidator cAValidator;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CertificateAuthorityModelMapper cAEntityMapper;

    @Mock
    SystemRecorder systemRecorder;

    CertificateAuthority certificateAuthority = new CertificateAuthority();
    CertificateAuthorityData certificateAuthorityData;

    @Before
    public void setUp() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

        certificateAuthority = entitiesSetUpData.getCertificateAuthority();
        certificateAuthority.setName("ENM_RootCA");
        certificateAuthorityData = entitiesSetUpData.getCertificateAuthorityData();

    }

    @Test
    public void testCreateCA() throws CertificateException {
        Mockito.doNothing().when(cAValidator).validateCreate(certificateAuthority);
        Mockito.doNothing().when(cAEntityPersistenceHandler).persistCA(certificateAuthority);
        Mockito.when(persistenceManager.findEntityByName(CertificateAuthorityData.class, "ENM_RootCA", "name")).thenReturn(certificateAuthorityData);
        Mockito.when(cAEntityMapper.toAPIModel(certificateAuthorityData)).thenReturn(certificateAuthority);
        cAEntityManager.createCA(certificateAuthority);
    }

    @Test
    public void testUpdateCA() throws CertificateException {
        Mockito.doNothing().when(cAValidator).validateUpdate(certificateAuthority);
        Mockito.doNothing().when(cAEntityPersistenceHandler).updateCA(certificateAuthority);
        Mockito.when(persistenceManager.findEntityByName(CertificateAuthorityData.class, "ENM_RootCA", "name")).thenReturn(certificateAuthorityData);
        Mockito.doNothing().when(cAEntityPersistenceHandler).updateCertificateStatus(certificateAuthorityData, certificateAuthority.getStatus());
        Mockito.when(cAEntityMapper.toAPIModel(certificateAuthorityData)).thenReturn(certificateAuthority);
        cAEntityManager.updateCA(certificateAuthority);
    }

    @Test
    public void testDeleteCA() throws CertificateException {
        certificateAuthorityData.setStatus(CAStatus.NEW);
        Mockito.doNothing().when(cAValidator).checkEntityNameFormat(certificateAuthority.getName());
        Mockito.when(cAEntityPersistenceHandler.getCAData(certificateAuthority)).thenReturn(certificateAuthorityData);

        Mockito.when(persistenceManager.findEntityByName(CertificateAuthorityData.class, "ENM_RootCA", "name")).thenReturn(certificateAuthorityData);
        Mockito.doNothing().when(cAEntityPersistenceHandler).updateCertificateStatus(certificateAuthorityData, certificateAuthority.getStatus());
        Mockito.when(cAEntityMapper.toAPIModel(certificateAuthorityData)).thenReturn(certificateAuthority);
        cAEntityManager.deleteCA(certificateAuthority);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testDeleteCA_EntityServiceException() throws CertificateException {
        certificateAuthorityData.setStatus(CAStatus.NEW);
        Mockito.doNothing().when(cAValidator).checkEntityNameFormat(certificateAuthority.getName());
        Mockito.when(cAEntityPersistenceHandler.getCAData(certificateAuthority)).thenReturn(certificateAuthorityData);
        Mockito.when(cAValidator.isCACanBeDeleted(CAStatus.NEW)).thenReturn(true);
        Mockito.when(persistenceManager.findEntityByName(CertificateAuthorityData.class, "ENM_RootCA", "name")).thenReturn(certificateAuthorityData);
        Mockito.doNothing().when(cAEntityPersistenceHandler).updateCertificateStatus(certificateAuthorityData, certificateAuthority.getStatus());
        Mockito.when(cAEntityMapper.toAPIModel(certificateAuthorityData)).thenReturn(certificateAuthority);
        Mockito.doThrow(new CoreEntityServiceException()).when(cAEntityPersistenceHandler).deleteCA(certificateAuthorityData);
        cAEntityManager.deleteCA(certificateAuthority);
    }

    @Test
    public void testDeletCA_CAStatusINACTIVE() throws CertificateException {
        certificateAuthorityData.setStatus(CAStatus.INACTIVE);
        Mockito.doNothing().when(cAValidator).checkEntityNameFormat(certificateAuthority.getName());
        Mockito.when(cAEntityPersistenceHandler.getCAData(certificateAuthority)).thenReturn(certificateAuthorityData);
        Mockito.when(cAValidator.isCACanBeDeleted(CAStatus.INACTIVE)).thenReturn(true);
        Mockito.when(persistenceManager.findEntityByName(CertificateAuthorityData.class, "ENM_RootCA", "name")).thenReturn(certificateAuthorityData);
        Mockito.doNothing().when(cAEntityPersistenceHandler).updateCertificateStatus(certificateAuthorityData, certificateAuthority.getStatus());
        cAEntityManager.deleteCA(certificateAuthority);
        verify(cAEntityPersistenceHandler, times(1)).updateCAStatus(certificateAuthorityData, CAStatus.DELETED);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testUpdateCA_ServiceException() throws CertificateException {
        Mockito.doNothing().when(cAValidator).validateUpdate(certificateAuthority);
        Mockito.doNothing().when(cAEntityPersistenceHandler).updateCA(certificateAuthority);
        Mockito.when(persistenceManager.findEntityByName(CertificateAuthorityData.class, "ENM_RootCA", "name")).thenThrow(new PersistenceException());

        cAEntityManager.updateCA(certificateAuthority);
    }

}
