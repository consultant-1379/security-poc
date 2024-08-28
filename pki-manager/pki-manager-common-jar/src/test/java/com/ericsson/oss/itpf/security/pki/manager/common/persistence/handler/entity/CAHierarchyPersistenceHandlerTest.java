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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.persistence.PersistenceException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.Duration;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.ModelMapperv1;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.TreeNode;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;

/**
 * JUnit Class to test {@link CAHierarchyPersistenceHandler} class.
 *
 * @author xnagcho
 * @version 1.1.30
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CAHierarchyPersistenceHandlerTest extends CAHierarchyPersistenceHandlerBaseTest {

    @Mock
    ModelMapperv1 modelMapperv1;

    @Spy
    Logger logger = LoggerFactory.getLogger(CAHierarchyPersistenceHandler.class);

    /**
     * Method to setup Data required to perform tests on {@link CAHierarchyPersistenceHandler}
     *
     * @throws DatatypeConfigurationException
     *             thrown when invalid {@link Duration} is given.
     */
    @Before
    public void setup() throws DatatypeConfigurationException {
        setupDataEntities();
        setupCAEntities();
        setupTreeNodes();
    }

    /**
     * Method to setup required method mocks for testing {@link CAHierarchyPersistenceHandler}
     */
    private void mockSetup() {
        mockFindEntitiesWhereMethod(rootCAsList, IS_ROOT_CA_PATH, true, CAEntityData.class);

        mockCertificateProfilesWithRootCAIssuer();
        mockCertificateProfilesWithSubCA1Issuer();

        mockFindEntitiesWhereMethod(null, ISSUER_DATA, subCA2Data, CertificateProfileData.class);
        mockFindEntitiesWhereMethod(null, ISSUER_DATA, subCA3Data, CertificateProfileData.class);

        mockEntityProfiles();
        mockCAEntities();

        mockCAEntityMapper();

    }

    /**
     * Positive Test: retrieving root CA Hierarchies.
     */
    @Test
    public void testGetCAHeirarchy_WhenRootCAsExistsInSystem() {
        mockSetup();

        final List<TreeNode<CAEntity>> expectedNodes = new ArrayList<TreeNode<CAEntity>>();
        expectedNodes.add(expectedRootNode);

        final List<TreeNode<CAEntity>> treeNodes = cAHierarchyBuilder.getRootCAHierarchies();

        assertEquals(expectedNodes, treeNodes);
        assertEquals(1, treeNodes.size());
    }

    /**
     * Negative Test: When no root CAs found in system, {@link EntityNotFoundException} should be thrown.
     */
    @Test(expected = CANotFoundException.class)
    public void testGetCAHeirarchy_WhenNoRootCAsExistsInSystem() {
        final List<CAEntityData> blankRootCAsList = new ArrayList<CAEntityData>();
        final Map<String, Object> input = new HashMap<String, Object>();

        input.put(IS_ROOT_CA_PATH, true);

        when(persistenceManager.findEntitiesWhere(CAEntityData.class, input)).thenReturn(blankRootCAsList);
        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.CA_ENTITY)).thenReturn(modelMapper);

        cAHierarchyBuilder.getRootCAHierarchies();
    }

    /**
     * Positive Test: Retrieving CA Hierarchy when only one root CA is present in system.
     */
    @Test
    public void testGetCAHeirarchy_WhenOnlyOneCAExistsInSystem() {
        final Map<String, Object> input = new HashMap<String, Object>();
        input.put(IS_ROOT_CA_PATH, true);

        final List<CAEntityData> onlyOneCA = new ArrayList<CAEntityData>();
        onlyOneCA.add(onlyOneRootCAData);

        when(persistenceManager.findEntitiesWhere(CAEntityData.class, input)).thenReturn(onlyOneCA);
        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.CA_ENTITY)).thenReturn(modelMapper);
        when(modelMapperFactoryv1.getEntitiesMapper(EntityType.CA_ENTITY)).thenReturn(modelMapperv1);
        when(modelMapper.toAPIFromModel(onlyOneRootCAData)).thenReturn(onlyOneRootCA);
        when(modelMapperv1.toApi(onlyOneRootCAData, MappingDepth.LEVEL_1)).thenReturn(onlyOneRootCA);

        final List<TreeNode<CAEntity>> treeNodes = cAHierarchyBuilder.getRootCAHierarchies();

        assertEquals(expectedOnlyOneNode, treeNodes.get(0));
        assertEquals(1, treeNodes.size());
    }

    /**
     * Positive Test: Retrieving CA Heirarchy absed on CA Name.
     */
    @Test
    public void testGetCAHeirarchyWithName_WithCANameGivenExistsInSystem() {
        mockSetup();
        final TreeNode<CAEntity> treeNode = cAHierarchyBuilder.getCAHierarchyByName(TEST_ENTITY_NAME);

        assertEquals(expectedSubCA1Node, treeNode);
    }

    /**
     * Negative Test: When retrieving CA Hierarchy based on CA Name. If CA with given name is not found, {@link CANotFoundException} should be thrown.
     */
    @Test(expected = CANotFoundException.class)
    public void testGetCAHeirarchyWithName_WhenCAWithNameNotExistsInSystem() {
        final Map<String, Object> inputForCAName = new HashMap<String, Object>();
        inputForCAName.put(CA_NAME_PATH, INVALID_CA_NAME);

        when(persistenceManager.findEntitiesWhere(CAEntityData.class, inputForCAName)).thenReturn(null);

        cAHierarchyBuilder.getCAHierarchyByName(INVALID_CA_NAME);
    }

    /**
     * Negative Test: when any exception occurs in Entities Mapper, {@link EntityServiceException} should be thrown.
     */
    @Test(expected = InvalidEntityException.class)
    public void testGetCAHeirarchy_WhenErrorOccuredInMapper() {
        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.CA_ENTITY)).thenThrow(new InvalidEntityException());
        when(modelMapperFactoryv1.getEntitiesMapper(EntityType.CA_ENTITY)).thenThrow(new InvalidEntityException());
        mockFindEntitiesWhereMethod(rootCAsList, IS_ROOT_CA_PATH, true, CAEntityData.class);

        cAHierarchyBuilder.getRootCAHierarchies();
    }

    /**
     * Negative Test: when any {@link PersistenceException} occurs in retrieving Root CAs, {@link EntityServiceException} should be thrown.
     */
    @Test(expected = EntityServiceException.class)
    public void testGetCAHeirarchy_WhenDBErrorOccuredInGettingRootCAs() {
        mockCAEntityMapper();

        final Map<String, Object> input = new HashMap<String, Object>();
        input.put(IS_ROOT_CA_PATH, true);
        when(persistenceManager.findEntitiesWhere(CAEntityData.class, input)).thenThrow(PersistenceException.class);

        cAHierarchyBuilder.getRootCAHierarchies();
    }

    /**
     * Negative Test: when any {@link PersistenceException} occurs in retrieving CA with given name, {@link EntityServiceException} should be thrown.
     */
    @Test(expected = EntityServiceException.class)
    public void testGetCAHeirarchyWithName_WhenDBErrorInGettingCAWithName() {
        mockCAEntityMapper();

        final Map<String, Object> inputForCAName = new HashMap<String, Object>();
        inputForCAName.put(CA_NAME_PATH, TEST_ENTITY_NAME);
        when(persistenceManager.findEntitiesWhere(CAEntityData.class, inputForCAName)).thenThrow(PersistenceException.class);

        cAHierarchyBuilder.getCAHierarchyByName(TEST_ENTITY_NAME);
    }

    /**
     * Negative Test: when any {@link PersistenceException} occurs in retrieving certificate profiles, {@link EntityServiceException} should be thrown.
     */
    @Test(expected = EntityServiceException.class)
    public void testGetCAHeirarchy_WhenDBErrorInGettingCertificateProfiles() {
        mockCAEntityMapper();
        mockFindEntitiesWhereMethod(rootCAsList, IS_ROOT_CA_PATH, true, CAEntityData.class);

        final List<CertificateProfileData> subCAsCertificateProfiles = new ArrayList<CertificateProfileData>();
        subCAsCertificateProfiles.add(subCA1_certificateProfileData);
        final Map<String, Object> rootCA_as_issuer_input = new HashMap<String, Object>();
        rootCA_as_issuer_input.put(ISSUER_DATA, rootCAData);
        when(persistenceManager.findEntitiesWhere(CertificateProfileData.class, rootCA_as_issuer_input)).thenThrow(PersistenceException.class);

        cAHierarchyBuilder.getRootCAHierarchies();
    }

    /**
     * Negative Test: when any {@link PersistenceException} occurs in retrieving entity profiles, {@link EntityServiceException} should be thrown.
     */
    @Test(expected = EntityServiceException.class)
    public void testGetCAHeirarchy_WhenDBErrorInGettingEntityProfiles() {
        mockCAEntityMapper();
        mockFindEntitiesWhereMethod(rootCAsList, IS_ROOT_CA_PATH, true, CAEntityData.class);
        mockCertificateProfilesWithRootCAIssuer();

        final List<EntityProfileData> subCA1_entityProfiles = new ArrayList<EntityProfileData>();
        subCA1_entityProfiles.add(subCA1_EntityProfileData);
        final Map<String, Object> subCA1_cp_input = new HashMap<String, Object>();
        subCA1_cp_input.put(CERTIFICATEPROFILE_DATA, subCA1_certificateProfileData);
        when(persistenceManager.findEntitiesWhere(EntityProfileData.class, subCA1_cp_input)).thenThrow(PersistenceException.class);

        cAHierarchyBuilder.getRootCAHierarchies();
    }

    /**
     * Negative Test: when any {@link PersistenceException} occurs in retrieving CA Entities, {@link EntityServiceException} should be thrown.
     */
    @Test(expected = EntityServiceException.class)
    public void testGetCAHeirarchy_WhenDBErrorInGettingSubCAEntities() {
        mockCAEntityMapper();
        mockFindEntitiesWhereMethod(rootCAsList, IS_ROOT_CA_PATH, true, CAEntityData.class);
        mockCertificateProfilesWithRootCAIssuer();
        mockEntityProfiles();

        final List<CAEntityData> subCA1_EntityDatas = new ArrayList<CAEntityData>();
        subCA1_EntityDatas.add(subCA1Data);
        final Map<String, Object> subCA1_ep_input = new HashMap<String, Object>();
        subCA1_ep_input.put(ENTITYPROFILE_DATA, subCA1_EntityProfileData);
        when(persistenceManager.findEntitiesWhere(CAEntityData.class, subCA1_ep_input)).thenThrow(PersistenceException.class);

        cAHierarchyBuilder.getRootCAHierarchies();
    }

}
