package com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl.service;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.kaps.common.persistence.handler.TAFKeyPairPersistenceHandler;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.TAFDataPersistenceHandler;

@RunWith(MockitoJUnitRunner.class)

public class TAFCoreEntityManagementServiceLocalBeanTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(CAEntityManagementServiceBean.class);

    @InjectMocks
    TAFCoreEntityManagementServiceLocalBean tafCoreEntityManagementServiceLocalBean;

    @Mock
    private TAFDataPersistenceHandler tafDataPersistanceHandler;

    @Mock
    TAFKeyPairPersistenceHandler tafKeyPairPersistenceHandler;

    @Test
    public void testDeleteCAEntityDataByName() {
        ArrayList<Long> certIdList = new ArrayList<Long>();
        ArrayList<String> entityList = new ArrayList<String>();
        entityList.add("ENTITY");
        certIdList.add((long) 10);
        certIdList.add((long) 50);
        Mockito.when(tafDataPersistanceHandler.getDataEntityId(Mockito.anyString(), Mockito.anyMap())).thenReturn(certIdList.get(0));
        Mockito.when(tafDataPersistanceHandler.getEntityNameListByPartOfName(Mockito.anyString(), Mockito.anyString())).thenReturn(entityList);
        Mockito.doNothing().when(tafDataPersistanceHandler).deleteTAFEntity(Mockito.anyString(), Mockito.anyMap());
        tafCoreEntityManagementServiceLocalBean.deleteTafEntities("ENTITY");
        Mockito.when(tafDataPersistanceHandler.getDataEntityIdList(Mockito.anyString(), Mockito.anyMap())).thenReturn(certIdList);
        Mockito.when(tafDataPersistanceHandler.getDataEntityId(Mockito.anyString(), Mockito.anyMap())).thenReturn(certIdList.get(1));
        tafCoreEntityManagementServiceLocalBean.deleteCAEntityForeignKeyMappings(certIdList.get(0), certIdList.get(1));
        tafCoreEntityManagementServiceLocalBean.deleteCAEntityDataByName("ENTITY");
    }

    @Test
    public void testGetTafCAEntityNames() {
        tafCoreEntityManagementServiceLocalBean.getTafCAEntityNames("KEY");
    }

    @Test
    public void testDeleteTafEntities() {
        final List<Long> certIdsList = new ArrayList<Long>();
        certIdsList.add((long) 40);
        certIdsList.add((long) 42);
        Mockito.when(tafDataPersistanceHandler.getDataEntityId(Mockito.anyString(), Mockito.anyMap())).thenReturn(certIdsList.get(0));
        Mockito.when(tafDataPersistanceHandler.getDataEntityIdList(Mockito.anyString(), Mockito.anyMap())).thenReturn(certIdsList);
        tafCoreEntityManagementServiceLocalBean.deleteTafEntities(Mockito.anyString());
        tafCoreEntityManagementServiceLocalBean.deleteCAEntityDataByName(Mockito.anyString());
        Mockito.doNothing().when(tafDataPersistanceHandler).deleteTAFEntity(Mockito.anyString(), Mockito.anyMap());
        tafCoreEntityManagementServiceLocalBean.deleteCAEntityForeignKeyMappings(certIdsList.get(0), certIdsList.get(1));
    }

    @Test
    public void testDeleteCAEntityForeignKeyMappings() {
        ArrayList<Long> certIdList = new ArrayList<Long>();
        certIdList.add((long) 5);
        certIdList.add((long) 6);
        Mockito.when(tafDataPersistanceHandler.getDataEntityId(Mockito.anyString(), Mockito.anyMap())).thenReturn(certIdList.get(0));
        Mockito.doNothing().when(tafDataPersistanceHandler).deleteTAFEntity(Mockito.anyString(), Mockito.anyMap());
        tafCoreEntityManagementServiceLocalBean.deleteCAEntityForeignKeyMappings(certIdList.get(0), certIdList.get(1));
    }

    @Test
    public void testDeleteTAFKapsData() throws KeyIdentifierNotFoundException,
            KeyAccessProviderServiceException {
        tafCoreEntityManagementServiceLocalBean
                .deleteTAFKapsData("TAF_PKI_KAPS");
        Mockito.doNothing().when(tafKeyPairPersistenceHandler)
                .deleteTAFCaKeys(Mockito.anyList());
    }
}
