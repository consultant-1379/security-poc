package com.ericsson.oss.itpf.security.pki.manager.rest.local.service.impl;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

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
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl.service.TAFCoreEntityManagementServiceLocalBean;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile.EntityAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;

@RunWith(MockitoJUnitRunner.class)

public class TAFEntityManagementServiceLocalBeanTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(TAFEntityManagementServiceLocalBeanTest.class);

    @InjectMocks
    TAFEntityManagementServiceLocalBean tafCoreEntityManagementServiceLocalBean;

    @Mock
    private TAFDataPersistenceHandler tafDataPersistanceHandler;

    @Mock
    TAFKeyPairPersistenceHandler tafKeyPairPersistenceHandler;

    @Inject
    private EntityAuthorizationHandler entityAuthorizationHandler;

    @Inject
    private TAFCoreEntityManagementServiceLocalBean coreTafPersistanceHandler;

    @Test
    public void testGetEndEntityNamesFrmPKIManager() {
        ArrayList<String> entityNames = new ArrayList<String>();
        tafCoreEntityManagementServiceLocalBean.getEndEntityNamesFrmPKIManager("$$$");
        Mockito.when(tafDataPersistanceHandler.getEntityNameListByPartOfName(Mockito.anyString(),Mockito.anyString())).thenReturn(entityNames);
    }

    @Test
    public void testGetEndEntityNamesFrmPKIManager_Positive() {
        ArrayList<String> entityNames = new ArrayList<String>();
        tafCoreEntityManagementServiceLocalBean.getEndEntityNamesFrmPKIManager("TAF_PKI");
        Mockito.when(tafDataPersistanceHandler.getEntityNameListByPartOfName("select name from entity where name LIKE :name_part","TAF_PKI"))
        .thenReturn(entityNames);
    }

    @Test
    public void testGetCAEntityNamesFrmPKIManager() {
        ArrayList<String> caEntityNames = new ArrayList<String>();
        tafCoreEntityManagementServiceLocalBean.getCAEntityNamesFrmPKIManager("$$$");
        Mockito.when(tafDataPersistanceHandler.getEntityNameListByPartOfName(Mockito.anyString(),Mockito.anyString())).thenReturn(caEntityNames);
    }

    @Test(expected=Exception.class)
    public void testDeleteEndEntitiesFrmPKICore() {
        tafCoreEntityManagementServiceLocalBean.deleteEndEntitiesFrmPKICore("$$$");
        entityAuthorizationHandler.authorizeDeleteTAFEntity();
        coreTafPersistanceHandler.deleteTafEntities("$$$");
    }

    @Test(expected=Exception.class)
    public void testGetCAEntityNamesFromPKICore() {
        tafCoreEntityManagementServiceLocalBean.getCAEntityNamesFromPKICore("$$$");
    }

    @Test(expected=Exception.class)
    public void testGetCAEntityNamesFromPKICore_Positive() {
        tafCoreEntityManagementServiceLocalBean.getCAEntityNamesFromPKICore("TAF_PKI");
    }

    @Test
    public void testDeleteCaKeysFrmKaps() {
        tafCoreEntityManagementServiceLocalBean.deleteCaKeysFrmKaps("$$$");
    }
}