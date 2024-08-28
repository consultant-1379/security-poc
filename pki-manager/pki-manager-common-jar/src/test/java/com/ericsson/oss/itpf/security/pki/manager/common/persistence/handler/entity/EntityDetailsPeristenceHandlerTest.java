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

import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.manager.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.data.EntityCategorySetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntitiesModelMapperFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntityDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityCategoryData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;

/**
 * Test class for {@link EntityDetailsPeristenceHandler}
 * 
 */
@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class EntityDetailsPeristenceHandlerTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(EntityDetailsPeristenceHandlerTest.class);

    @InjectMocks
    EntityDetailsPeristenceHandler entityDetailsPersistenceHandler;

    @Mock
    EntitiesModelMapperFactory entityModelMapperFactory;

    @Mock
    EntityFilterDynamicQueryBuilder entityFilterDynamicQueryBuilder;

    @Mock
    ModelMapper modelMapper;

    @Mock
    PersistenceManager persistenceManager;

    private Entity entity;
    private EntityData entityData;
    private EntityCategory entityCategory;
    private EntityCategoryData entityCategoryData;
    private EntityInfo entityInfo;

    /**
     * Method to get the dummy data for testing
     */
    @Before
    public void setUp() {

        final EntityCategorySetUpData entityCategorySetUpData = new EntityCategorySetUpData();
        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityCategory = entityCategorySetUpData.getEntityCategory();
        entityCategoryData = entityCategorySetUpData.getEntityCategoryData();

        final List<EntityData> entityDataList = entitiesSetUpData.getEntityDataList();
        final List<Entity> entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entityData = entityDataList.get(0);
        final long id = entity.getEntityInfo().getId();
        final String name = entity.getEntityInfo().getName();
        entityInfo = entity.getEntityInfo();

        when(entityModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(modelMapper);
        when(modelMapper.fromAPIToModel(entity)).thenReturn(entityData);
        when(modelMapper.toAPIFromModel(entityData)).thenReturn(entity);

        when(persistenceManager.findEntityByName(EntityData.class, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(entityData);

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(entityData);

    }

    /**
     * Method to test getEntityDetails() method WithFilter in positive scenario
     */
    @Test
    public void testGetEntityDetailsWithFilter() {

        final EntitiesFilter entitiesFilter = getEntitiesFilter();
        final StringBuilder dynamicQuery = new StringBuilder();

        final EntityProfile entityProfile = new EntityProfile();
        final Algorithm algorithm = new Algorithm();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        final BigInteger bigInteger = new BigInteger("1");

        final List<Object[]> entityDetails = new ArrayList<Object[]>();
        Object[] listContainer = new Object[20];
        listContainer[0] = bigInteger;
        listContainer[1] = true;
        listContainer[2] = certificateAuthority.getName();
        listContainer[3] = algorithm;
        listContainer[4] = algorithm;
        listContainer[5] = certificateAuthority.getSubject();
        listContainer[6] = certificateAuthority.getSubjectAltName();
        listContainer[7] = 1;
        listContainer[8] = bigInteger;
        listContainer[9] = algorithm.getKeySize();
        listContainer[10] = algorithm.getName();
        listContainer[11] = algorithm.getOid();
        listContainer[12] = algorithm.isSupported();
        listContainer[13] = algorithm.getType();
        listContainer[14] = bigInteger;
        listContainer[15] = entityProfile.getName();
        listContainer[16] = true;
        listContainer[17] = bigInteger;

        entityDetails.add(listContainer);

        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("entityName", entitiesFilter.getName());
        attributes.put("statusList", getEntityStatusList(entitiesFilter));
        when(entityFilterDynamicQueryBuilder.build(entitiesFilter, dynamicQuery)).thenReturn(attributes);
        when(persistenceManager.findEntitiesByNativeQuery(Mockito.anyString(), Mockito.anyMap(), Mockito.anyInt(), Mockito.anyInt())).thenReturn(entityDetails);
        final List<AbstractEntityDetails> expectedEntityDetails = entityDetailsPersistenceHandler.getEntityDetails(entitiesFilter);

        assertNotNull(expectedEntityDetails);
    }

    @Test
    public void testGetEntityDetailsWithFilter_entity() {

        final EntitiesFilter entitiesFilter = getEntitiesFilter();
        final StringBuilder dynamicQuery = new StringBuilder();

        final EntityInfo entityInfo = new EntityInfo();
        EntityProfile entityProfile = new EntityProfile();
        final Algorithm algorithm = new Algorithm();
        final CertificateAuthority ca = new CertificateAuthority();
        final BigInteger bigInteger = new BigInteger("1");

        final List<Object[]> entityDetails = new ArrayList<Object[]>();
        Object[] listContainer = new Object[20];
        listContainer[0] = bigInteger;
        listContainer[1] = true;
        listContainer[2] = ca.getName();
        listContainer[3] = entityInfo.getOTP();
        listContainer[4] = entityInfo.getOTPCount();
        listContainer[5] = ca.getSubject();
        listContainer[6] = ca.getSubjectAltName();
        listContainer[7] = 1;
        listContainer[8] = bigInteger;
        listContainer[9] = algorithm.getKeySize();
        listContainer[10] = algorithm.getName();
        listContainer[11] = algorithm.getOid();
        listContainer[12] = algorithm.isSupported();
        listContainer[13] = algorithm.getType();
        listContainer[14] = bigInteger;
        listContainer[15] = entityProfile.getName();
        listContainer[16] = false;
        listContainer[17] = bigInteger;

        entityDetails.add(listContainer);

        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("entityName", entitiesFilter.getName());
        attributes.put("statusList", getEntityStatusList(entitiesFilter));
        when(entityFilterDynamicQueryBuilder.build(entitiesFilter, dynamicQuery)).thenReturn(attributes);
        when(persistenceManager.findEntitiesByNativeQuery(Mockito.anyString(), Mockito.anyMap(), Mockito.anyInt(), Mockito.anyInt())).thenReturn(entityDetails);
        final List<AbstractEntityDetails> expectedEntityDetails = entityDetailsPersistenceHandler.getEntityDetails(entitiesFilter);

        assertNotNull(expectedEntityDetails);
    }

    private EntitiesFilter getEntitiesFilter() {

        final EntitiesFilter entitiesFilter = new EntitiesFilter();

        entitiesFilter.setCertificateAssigned(0);
        entitiesFilter.setId(1);
        entitiesFilter.setLimit(10);
        entitiesFilter.setName("rest%");
        entitiesFilter.setOffset(0);

        final List<EntityType> entityTypes = new ArrayList<EntityType>();

        entityTypes.add(EntityType.CA_ENTITY);
        entitiesFilter.setStatus(getStatusFilter());

        entitiesFilter.setType(entityTypes);
        return entitiesFilter;
    }

    private List<EntityStatus> getStatusFilter() {
        final List<EntityStatus> status = new ArrayList<EntityStatus>();

        return status;
    }

    private Set<Integer> getEntityStatusList(final EntitiesFilter entitiesFilter) {
        final Set<Integer> entityStatusList = new HashSet<Integer>();

        for (EntityStatus entityStatus : entitiesFilter.getStatus()) {
            entityStatusList.add(entityStatus.getId());
        }

        return entityStatusList;
    }

}
