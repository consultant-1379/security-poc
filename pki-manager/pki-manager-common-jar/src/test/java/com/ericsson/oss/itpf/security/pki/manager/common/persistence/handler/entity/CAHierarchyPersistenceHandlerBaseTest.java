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

import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.Duration;

import org.mockito.InjectMocks;
import org.mockito.Mock;

import com.ericsson.oss.itpf.security.pki.manager.common.data.CAEntityDataSetUp;
import com.ericsson.oss.itpf.security.pki.manager.common.data.CAEntitySetUp;
import com.ericsson.oss.itpf.security.pki.manager.common.data.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.data.EntityProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntitiesModelMapperFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entityv1.EntitiesModelMapperFactoryv1;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.ModelMapperv1;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.TreeNode;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;

/**
 * Base Class containing setup and mock data required for Testing {@link CAHierarchyPersistenceHandler}
 *
 * @author xnagcho
 * @version 1.1.30
 *
 */
public abstract class CAHierarchyPersistenceHandlerBaseTest {

    protected static final String CA_NAME_PATH = "certificateAuthorityData.name";
    protected static final String TEST_ENTITY_NAME = "ENM_CA";
    protected static final String IS_ROOT_CA_PATH = "certificateAuthorityData.rootCA";
    protected static final String ISSUER_DATA = "issuerData";
    protected static final String CERTIFICATEPROFILE_DATA = "certificateProfileData";
    protected static final String ENTITYPROFILE_DATA = "entityProfileData";
    protected static final String INVALID_CA_NAME = "InvalidCA";

    @InjectMocks
    CAHierarchyPersistenceHandler cAHierarchyBuilder;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    EntitiesModelMapperFactory entitiesModelMapperFactory;

    @Mock
    EntitiesModelMapperFactoryv1 modelMapperFactoryv1;

    @Mock
    ModelMapper modelMapper;

    @Mock
    ModelMapperv1 modelMapperv1;

    TreeNode<CAEntity> expectedRootNode, expectedSubCA1Node, expectedSubCA2Node, expectedSubCA3Node, expectedOnlyOneNode;

    List<CAEntityData> rootCAsList = new ArrayList<CAEntityData>();
    CertificateProfileData subCA1_certificateProfileData, subCA2_certificateProfileData, subCA3_certificateProfileData;
    EntityProfileData subCA1_EntityProfileData, subCA2_EntityProfileData, subCA3_EntityProfileData;
    CAEntityData onlyOneRootCAData, rootCAData, subCA1Data, subCA2Data, subCA3Data;
    CAEntity onlyOneRootCA, rootCA, subCA1, subCA2, subCA3;

    CertificateProfileSetUpData certificateProfileDataSetUp;
    EntityProfileSetUpData entityProfileDataSetUp;
    CAEntityDataSetUp caEntityDataSetUp;
    CAEntitySetUp caEntitySetUp;

    /**
     * Method that prepares Entities Data required for testing
     *
     * @throws DatatypeConfigurationException
     *             thrown when invalid {@link Duration} is specified.
     */
    protected void setupDataEntities() throws DatatypeConfigurationException {
        certificateProfileDataSetUp = new CertificateProfileSetUpData();
        entityProfileDataSetUp = new EntityProfileSetUpData();
        caEntityDataSetUp = new CAEntityDataSetUp();

        onlyOneRootCAData = caEntityDataSetUp.getCAEntity(10, "ENM_PKI_Root_CA", true, null, null, "CN=ENM_PKI_Root_CA", null);

        rootCAData = caEntityDataSetUp.getCAEntity(1, "ENM_PKI_Root_CA", true, null, null, "CN=ENM_PKI_Root_CA", null);

        subCA1_certificateProfileData = certificateProfileDataSetUp.getCertificateProfileData(2, "ENM_CA_CP", rootCAData, null);
        subCA1_EntityProfileData = entityProfileDataSetUp.getEntityProfileForCA(2, "ENM_CA_EP", "CN=ENM_CA", subCA1_certificateProfileData, null);
        subCA1Data = caEntityDataSetUp.getCAEntity(2, "ENM_CA", false, subCA1_EntityProfileData, null, "CN=ENM_CA", null);

        subCA2_certificateProfileData = certificateProfileDataSetUp.getCertificateProfileData(3, "NE_CA_CP", rootCAData, null);
        subCA2_EntityProfileData = entityProfileDataSetUp.getEntityProfileForCA(3, "NE_CA_EP", "CN=NE_CA", subCA2_certificateProfileData, null);
        subCA2Data = caEntityDataSetUp.getCAEntity(3, "NE_CA", false, subCA2_EntityProfileData, null, "CN=NE_CA", null);

        subCA3_certificateProfileData = certificateProfileDataSetUp.getCertificateProfileData(4, "ENM_System_CA_CP", subCA1Data, null);
        subCA3_EntityProfileData = entityProfileDataSetUp.getEntityProfileForCA(4, "ENM_System_CA_EP", "CN=ENM_System_CA", subCA3_certificateProfileData, null);
        subCA3Data = caEntityDataSetUp.getCAEntity(4, "ENM_System_CA", false, subCA3_EntityProfileData, null, "CN=ENM_System_CA", null);

        rootCAsList.add(rootCAData);
    }

    /**
     * Method for setting up {@link CAEntityData}
     */
    protected void setupCAEntities() {
        caEntitySetUp = new CAEntitySetUp();

        rootCA = caEntitySetUp.getCAEntity("ENM_PKI_Root_CA");
        subCA1 = caEntitySetUp.getCAEntity("ENM_CA");
        subCA2 = caEntitySetUp.getCAEntity("NE_CA");
        subCA3 = caEntitySetUp.getCAEntity("ENM_System_CA");
        onlyOneRootCA = caEntitySetUp.getCAEntity("ENM_PKI_Root_CA");
    }

    /**
     * Method to setup data for expected TreeNodes
     */
    protected void setupTreeNodes() {
        expectedRootNode = getTreeNode(rootCA, null);
        expectedSubCA1Node = getTreeNode(subCA1, expectedRootNode);
        expectedSubCA2Node = getTreeNode(subCA2, expectedRootNode);
        expectedSubCA3Node = getTreeNode(subCA3, expectedSubCA2Node);
        expectedOnlyOneNode = getTreeNode(onlyOneRootCA, null);

        expectedRootNode.setChilds(getChildList(expectedSubCA1Node, expectedSubCA2Node));
        expectedSubCA1Node.setChilds(getChildList(expectedSubCA3Node));
    }

    private TreeNode<CAEntity> getTreeNode(final CAEntity data, final TreeNode<CAEntity> parentCA) {
        final TreeNode<CAEntity> treeNode = new TreeNode<CAEntity>();
        treeNode.setData(data);
        treeNode.setParent(parentCA);

        return treeNode;
    }

    private List<TreeNode<CAEntity>> getChildList(final TreeNode<CAEntity>... childCAs) {
        final List<TreeNode<CAEntity>> childNodes = new ArrayList<TreeNode<CAEntity>>();

        for (final TreeNode<CAEntity> childCA : childCAs) {
            childNodes.add(childCA);
        }

        return childNodes;
    }

    /**
     * Method to mock FindEntitiesWhere method in {@link PersistenceManager}
     *
     * @param datas
     *            Data to be returned in mocked method.
     * @param inputName
     *            Input field name for persistence manager.
     * @param inputValue
     *            Input value for persistence manager.
     * @param dataClass
     *            {@link Class} of JPA Entity type that is to be returned.
     */
    protected <T> void mockFindEntitiesWhereMethod(final List<T> datas, final String inputName, final Object inputValue, final Class<T> dataClass) {
        final Map<String, Object> input = new HashMap<String, Object>();
        input.put(inputName, inputValue);
        when(persistenceManager.findEntitiesWhere(dataClass, input)).thenReturn(datas);
    }

    /**
     * Method to mock {@link CAEntityMapper}
     */
    protected void mockCAEntityMapper() {
        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.CA_ENTITY)).thenReturn(modelMapper);
        when(modelMapperFactoryv1.getEntitiesMapper(EntityType.CA_ENTITY)).thenReturn(modelMapperv1);

        when(modelMapperv1.toApi(rootCAData, MappingDepth.LEVEL_1)).thenReturn(rootCA);
        when(modelMapperv1.toApi(subCA1Data, MappingDepth.LEVEL_1)).thenReturn(subCA1);
        when(modelMapperv1.toApi(subCA2Data, MappingDepth.LEVEL_1)).thenReturn(subCA2);
        when(modelMapperv1.toApi(subCA3Data, MappingDepth.LEVEL_1)).thenReturn(subCA3);

        when(modelMapper.toAPIFromModel(rootCAData)).thenReturn(rootCA);
        when(modelMapper.toAPIFromModel(subCA1Data)).thenReturn(subCA1);
        when(modelMapper.toAPIFromModel(subCA2Data)).thenReturn(subCA2);
        when(modelMapper.toAPIFromModel(subCA3Data)).thenReturn(subCA3);

    }

    /**
     * Method to mock {@link CertificateProfileData} in which rootCA is issuer.
     */
    protected void mockCertificateProfilesWithRootCAIssuer() {
        final List<CertificateProfileData> subCAsCertificateProfiles = new ArrayList<CertificateProfileData>();
        subCAsCertificateProfiles.add(subCA1_certificateProfileData);
        subCAsCertificateProfiles.add(subCA2_certificateProfileData);
        mockFindEntitiesWhereMethod(subCAsCertificateProfiles, ISSUER_DATA, rootCAData, CertificateProfileData.class);
    }

    /**
     * Method to mock Certificate profiles in which subCA is issuer
     */
    protected void mockCertificateProfilesWithSubCA1Issuer() {
        final List<CertificateProfileData> subCAsCertificateProfiles_1 = new ArrayList<CertificateProfileData>();
        subCAsCertificateProfiles_1.add(subCA3_certificateProfileData);
        mockFindEntitiesWhereMethod(subCAsCertificateProfiles_1, ISSUER_DATA, subCA1Data, CertificateProfileData.class);
    }

    /**
     * Method to mock Entity profiles
     */
    protected void mockEntityProfiles() {
        final List<EntityProfileData> subCA1_entityProfiles = new ArrayList<EntityProfileData>();
        subCA1_entityProfiles.add(subCA1_EntityProfileData);
        mockFindEntitiesWhereMethod(subCA1_entityProfiles, CERTIFICATEPROFILE_DATA, subCA1_certificateProfileData, EntityProfileData.class);

        final List<EntityProfileData> subCA2_entityProfiles = new ArrayList<EntityProfileData>();
        subCA2_entityProfiles.add(subCA2_EntityProfileData);
        mockFindEntitiesWhereMethod(subCA2_entityProfiles, CERTIFICATEPROFILE_DATA, subCA2_certificateProfileData, EntityProfileData.class);

        final List<EntityProfileData> subCA3_entityProfiles = new ArrayList<EntityProfileData>();
        subCA3_entityProfiles.add(subCA3_EntityProfileData);
        mockFindEntitiesWhereMethod(subCA3_entityProfiles, CERTIFICATEPROFILE_DATA, subCA3_certificateProfileData, EntityProfileData.class);
    }

    /**
     * Mock CA Entities
     */
    protected void mockCAEntities() {
        final List<CAEntityData> subCA1_EntityDatas = new ArrayList<CAEntityData>();
        subCA1_EntityDatas.add(subCA1Data);
        mockFindEntitiesWhereMethod(subCA1_EntityDatas, ENTITYPROFILE_DATA, subCA1_EntityProfileData, CAEntityData.class);

        final List<CAEntityData> subCA2_EntityDatas = new ArrayList<CAEntityData>();
        subCA2_EntityDatas.add(subCA2Data);
        mockFindEntitiesWhereMethod(subCA2_EntityDatas, ENTITYPROFILE_DATA, subCA2_EntityProfileData, CAEntityData.class);

        final List<CAEntityData> subCA3_EntityDatas = new ArrayList<CAEntityData>();
        subCA3_EntityDatas.add(subCA3Data);
        mockFindEntitiesWhereMethod(subCA3_EntityDatas, ENTITYPROFILE_DATA, subCA3_EntityProfileData, CAEntityData.class);

        mockFindEntitiesWhereMethod(subCA1_EntityDatas, CA_NAME_PATH, TEST_ENTITY_NAME, CAEntityData.class);
    }
}
