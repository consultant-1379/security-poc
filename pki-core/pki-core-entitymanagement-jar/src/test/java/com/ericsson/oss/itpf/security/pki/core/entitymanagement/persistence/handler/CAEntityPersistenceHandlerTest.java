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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.persistence.handler;

import static org.mockito.Mockito.when;

import java.security.cert.CertificateException;
import java.util.*;

import javax.persistence.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateAuthorityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.common.utils.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class CAEntityPersistenceHandlerTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(CAEntityPersistenceHandler.class);

    @InjectMocks
    CAEntityPersistenceHandler caEntityPersistenceHandler;

    @Mock
    CertificateAuthorityModelMapper modelMapper;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    Query query;

    CertificateAuthority certificateAuthority;
    CertificateAuthorityData certificateAuthorityData;

    long id;
    String name;

    @Before
    public void setUp() throws CertificateException {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

        certificateAuthority = entitiesSetUpData.getCertificateAuthority();
        certificateAuthorityData = entitiesSetUpData.getCertificateAuthorityData();

        id = certificateAuthority.getId();
        name = certificateAuthority.getName();

        when(modelMapper.fromAPIModel(certificateAuthority, OperationType.CREATE)).thenReturn(certificateAuthorityData);

        when(persistenceManager.findEntityByName(CertificateAuthorityData.class, name, EntitiesSetUpData.NAME_PATH)).thenReturn(certificateAuthorityData);

        when(modelMapper.toAPIModel(certificateAuthorityData)).thenReturn(certificateAuthority);

        when(persistenceManager.findEntityByIdAndName(CertificateAuthorityData.class, id, name, EntitiesSetUpData.NAME_PATH)).thenReturn(certificateAuthorityData);

    }

    @Test
    public void testCreateEntity() {

        caEntityPersistenceHandler.persistCA(certificateAuthority);
    }

    @Test(expected = CoreEntityAlreadyExistsException.class)
    public void testCreateEntityExistsException() {

        Mockito.doThrow(new EntityExistsException()).when(persistenceManager).createEntity(certificateAuthorityData);

        caEntityPersistenceHandler.persistCA(certificateAuthority);

    }

    @Test(expected = CoreEntityServiceException.class)
    public void testCreateTransactionRequiredException() {

        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).createEntity(certificateAuthorityData);

        caEntityPersistenceHandler.persistCA(certificateAuthority);

    }

    @Test
    public void testUpdateEntity() {

        caEntityPersistenceHandler.updateCA(certificateAuthority);

    }

    @Test(expected = CoreEntityServiceException.class)
    public void testUpdateEntityTransactionRequiredException() {

        when(modelMapper.fromAPIModel(certificateAuthority, OperationType.UPDATE)).thenReturn(certificateAuthorityData);
        when(persistenceManager.updateEntity(certificateAuthorityData)).thenThrow(new TransactionRequiredException());

        caEntityPersistenceHandler.updateCA(certificateAuthority);

    }

    @Test(expected = CoreEntityServiceException.class)
    public void testUpdateEntityRunTimeException() {

        when(modelMapper.fromAPIModel(certificateAuthority, OperationType.UPDATE)).thenReturn(certificateAuthorityData);
        when(persistenceManager.updateEntity(certificateAuthorityData)).thenThrow(new CoreEntityServiceException());

        caEntityPersistenceHandler.updateCA(certificateAuthority);

    }

    @Test
    public void testdeleteCA() {
        Mockito.doNothing().when(persistenceManager).deleteEntity(certificateAuthorityData);
        caEntityPersistenceHandler.deleteCA(certificateAuthorityData);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testdeleteCA_EntityServiceException() {
        Mockito.doThrow(new CoreEntityServiceException()).when(persistenceManager).deleteEntity(certificateAuthorityData);
        caEntityPersistenceHandler.deleteCA(certificateAuthorityData);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testdeleteCA_CoreEntityServiceException() {
        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).deleteEntity(certificateAuthorityData);
        caEntityPersistenceHandler.deleteCA(certificateAuthorityData);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testdeleteCA_PersistenceException() {
        Mockito.doThrow(new PersistenceException()).when(persistenceManager).deleteEntity(certificateAuthorityData);
        caEntityPersistenceHandler.deleteCA(certificateAuthorityData);
    }

    @Test(expected = CoreEntityInUseException.class)
    public void testCheckSubCAsUnderCA_EntityInUseException() {
        List<CertificateAuthorityData> subCAList = new ArrayList<CertificateAuthorityData>();
        certificateAuthorityData.setName("ENM_RootCA");
        certificateAuthorityData.setStatus(CAStatus.ACTIVE);
        subCAList.add(certificateAuthorityData);
        when(query.getResultList()).thenReturn(subCAList);

        caEntityPersistenceHandler.checkSubCAsUnderCA(subCAList);
    }

    @Test(expected = CoreEntityNotFoundException.class)
    public void testGetCAData_EntityNotFoundException() {

        Map<String, Object> parameters = new HashMap<String, Object>();
        List<CertificateAuthorityData> caDataList = new ArrayList<CertificateAuthorityData>();
        caDataList.add(certificateAuthorityData);
        certificateAuthority.setName("ENM_RootCA");
        certificateAuthority.setId(1L);

        when(persistenceManager.findEntitiesByAttributes(CertificateAuthorityData.class, parameters)).thenReturn(caDataList);

        caEntityPersistenceHandler.getCAData(certificateAuthority);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetCAData_EntityNull() {

        Map<String, Object> parameters = new HashMap<String, Object>();
        List<CertificateAuthorityData> caDataList = new ArrayList<CertificateAuthorityData>();
        caDataList.add(certificateAuthorityData);
        certificateAuthority.setName(null);
        certificateAuthority.setId(0);

        when(persistenceManager.findEntitiesByAttributes(CertificateAuthorityData.class, parameters)).thenReturn(caDataList);

        caEntityPersistenceHandler.getCAData(certificateAuthority);
    }

    @Test
    public void testUpdateCertificateStatus_Active() {

        CertificateData certificateData = new CertificateData();
        certificateData.setNotAfter(new Date());
        Set<CertificateData> certificateDatasSet = new HashSet<CertificateData>();
        certificateDatasSet.add(certificateData);
        certificateAuthorityData.setStatus(CAStatus.INACTIVE);
        certificateAuthorityData.setCertificateDatas(certificateDatasSet);

        caEntityPersistenceHandler.updateCertificateStatus(certificateAuthorityData, CAStatus.ACTIVE);
    }

    @Test
    public void testUpdateCertificateStatus_InActive() {

        CertificateData certificateData = new CertificateData();
        Set<CertificateData> certificateDatasSet = new HashSet<CertificateData>();
        certificateDatasSet.add(certificateData);
        certificateAuthorityData.setStatus(CAStatus.ACTIVE);
        certificateAuthorityData.setCertificateDatas(certificateDatasSet);

        caEntityPersistenceHandler.updateCertificateStatus(certificateAuthorityData, CAStatus.INACTIVE);
    }

}
