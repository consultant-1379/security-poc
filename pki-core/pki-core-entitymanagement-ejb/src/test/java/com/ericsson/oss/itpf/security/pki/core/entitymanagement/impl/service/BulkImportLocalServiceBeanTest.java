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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl.service;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateAuthorityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.EntityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl.EntityManager;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.validators.CAValidator;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.validators.EntityValidator;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException;

@RunWith(MockitoJUnitRunner.class)
public class BulkImportLocalServiceBeanTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityManagementServiceBean.class);

    @InjectMocks
    BulkImportLocalServiceBean bulkImportLocalServiceBean;

    @Mock
    EntityManager entitiesManager;

    @Mock
    EntityModelMapper entityMapper;

    @Mock
    CertificateAuthorityModelMapper cAEntityMapper;

    @Mock
    EntityPersistenceHandler entityPersistenceHandler;

    @Mock
    CAEntityPersistenceHandler caEntityPersistenceHandler;

    @Mock
    CAValidator cAValidator;

    @Mock
    EntityValidator entityValidator;

    List<EntityInfo> entityInfoList = new ArrayList<EntityInfo>();
    List<CertificateAuthority> certificateAuthorityList = new ArrayList<CertificateAuthority>();
    final EntityInfo entityInfo_1 = new EntityInfo();
    final EntityInfo entityInfo_2 = new EntityInfo();
    final EntityInfoData entityInfoData_1 = new EntityInfoData();
    final CertificateAuthority certificateAuthority_1 = new CertificateAuthority();
    final CertificateAuthorityData certificateAuthorityData_1 = new CertificateAuthorityData();

    @Before
    public void setup() {

        entityInfo_1.setId(1);
        entityInfo_1.setName("ENMService1");

        entityInfoData_1.setId(1);
        entityInfoData_1.setName("ENMService1");

        entityInfo_2.setId(1);
        entityInfo_2.setName("ENMService2");
        entityInfoList.add(entityInfo_1);
        entityInfoList.add(entityInfo_2);

        certificateAuthority_1.setName("RootCA_1");
        certificateAuthority_1.setId(1);
        certificateAuthorityData_1.setName("RootCA_1");
        certificateAuthorityData_1.setId(1);

        CertificateAuthority certificateAuthority_2 = new CertificateAuthority();
        certificateAuthority_2.setName("RootCA_2");
        certificateAuthority_2.setId(2);

        certificateAuthorityList.add(certificateAuthority_1);
        //certificateAuthorityList.add(certificateAuthority_2);
    }

    @Test
    public void testImport_EntityInfo() {
        bulkImportLocalServiceBean.importEntityInfo(entityInfoList);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testImport_EntityInfo_Exception() {

        Mockito.doThrow(new CoreEntityServiceException()).when(entityValidator).validateEntity(entityInfo_1, OperationType.CREATE);
        bulkImportLocalServiceBean.importEntityInfo(entityInfoList);
    }

    @Test(expected = CoreEntityAlreadyExistsException.class)
    public void testImport_EntityInfo_Persist_EntityAlreadyExistsException() {
        Mockito.doNothing().when(entityValidator).validateEntity(entityInfo_1, OperationType.CREATE);
        Mockito.when(entityMapper.fromAPIToModel(entityInfo_1, OperationType.CREATE)).thenReturn(entityInfoData_1);
        Mockito.doThrow(new CoreEntityAlreadyExistsException()).when(entityPersistenceHandler).persistEntityInfo(entityInfoData_1);
        bulkImportLocalServiceBean.importEntityInfo(entityInfoList);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testImport_EntityInfo_Persist_EntityServiceException() {
        Mockito.doNothing().when(entityValidator).validateEntity(entityInfo_1, OperationType.CREATE);
        Mockito.when(entityMapper.fromAPIToModel(entityInfo_1, OperationType.CREATE)).thenReturn(entityInfoData_1);
        Mockito.doThrow(new CoreEntityServiceException()).when(entityPersistenceHandler).persistEntityInfo(entityInfoData_1);
        bulkImportLocalServiceBean.importEntityInfo(entityInfoList);
    }

    @Test(expected = CoreEntityAlreadyExistsException.class)
    public void testImport_EntityInfo_EntityAlreadyExistsException() {
        Mockito.doThrow(new CoreEntityAlreadyExistsException()).when(entityValidator).validateEntity(entityInfo_1, OperationType.CREATE);
        bulkImportLocalServiceBean.importEntityInfo(entityInfoList);
    }

    @Test
    public void testImport_CertificateAuthority() {
        bulkImportLocalServiceBean.importCertificateAuthority(certificateAuthorityList);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testImport_CertificateAuthority_EntityServiceException() {

        Mockito.doThrow(new CoreEntityServiceException()).when(cAValidator).validateCAEntity(certificateAuthority_1, OperationType.CREATE);
        bulkImportLocalServiceBean.importCertificateAuthority(certificateAuthorityList);
    }

    @Test(expected = CoreEntityAlreadyExistsException.class)
    public void testImport_CertificateAuthority_EntityAlreadyExistsException() {
        Mockito.doThrow(new CoreEntityAlreadyExistsException()).when(cAValidator).validateCAEntity(certificateAuthority_1, OperationType.CREATE);
        bulkImportLocalServiceBean.importCertificateAuthority(certificateAuthorityList);
    }

    @Test(expected = CoreEntityAlreadyExistsException.class)
    public void testImport_CertificateAuthority_Persist_EntityAlreadyExistsException() {
        Mockito.doNothing().when(cAValidator).validateCAEntity(certificateAuthority_1, OperationType.CREATE);
        Mockito.when(cAEntityMapper.fromAPIModel(certificateAuthority_1, OperationType.CREATE)).thenReturn(certificateAuthorityData_1);
        Mockito.doThrow(new CoreEntityAlreadyExistsException()).when(caEntityPersistenceHandler).persistCertificateAuthorityData(certificateAuthorityData_1);
        bulkImportLocalServiceBean.importCertificateAuthority(certificateAuthorityList);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testImport_CertificateAuthority_Persist_EntityServiceException() {
        Mockito.doNothing().when(cAValidator).validateCAEntity(certificateAuthority_1, OperationType.CREATE);
        Mockito.when(cAEntityMapper.fromAPIModel(certificateAuthority_1, OperationType.CREATE)).thenReturn(certificateAuthorityData_1);
        Mockito.doThrow(new CoreEntityServiceException()).when(caEntityPersistenceHandler).persistCertificateAuthorityData(certificateAuthorityData_1);
        bulkImportLocalServiceBean.importCertificateAuthority(certificateAuthorityList);
    }
}
