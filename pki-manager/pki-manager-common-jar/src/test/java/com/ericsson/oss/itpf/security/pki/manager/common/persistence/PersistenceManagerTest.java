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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.sql.SQLException;
import java.util.*;

import javax.persistence.*;
import javax.persistence.criteria.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.data.TrustProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;

@RunWith(MockitoJUnitRunner.class)
public class PersistenceManagerTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(PersistenceManager.class);

    @InjectMocks
    private PersistenceManager persistenceManger;

    @Mock
    private EntityManager em;

    @Mock
    private CriteriaBuilder criteriaBuilder;

    @Mock
    private CriteriaQuery<TrustProfileData> criteriaQuery;

    @Mock
    private CriteriaQuery<Long> criteriaQueryLong;

    @Mock
    private TypedQuery<Long> typedQueryLong;

    @Mock
    private Root<TrustProfileData> root;

    @Mock
    private Predicate predicate;

    @Mock
    private TypedQuery<TrustProfileData> typedQuery;

    @Mock
    private Path<Object> path;

    @Mock
    Query queryEM;

    private List<TrustProfileData> trustProfileDataList;
    private TrustProfileData trustProfileData;
    private List<String> values;
    private Map<String, Object> input;
    private EntitiesFilter entitiesFilter;

    private long id;
    private String name;

    /**
     * Method to get the dummy data into TrustProfile and TrustProfileData
     */
    @Before
    public void setUp() {
        final TrustProfileSetUpData trustProfileSetUpData = new TrustProfileSetUpData();
        trustProfileDataList = trustProfileSetUpData.getTrustProfileDataList();
        trustProfileData = trustProfileDataList.get(0);
        id = trustProfileData.getId();
        name = trustProfileData.getName();
        values = trustProfileSetUpData.getValues();
        input = trustProfileSetUpData.getInput();

    }

    /**
     * Method to test getEntityManager in positive scenario
     */

    @Test
    public void testGetEntityManager() {
        assertEquals(persistenceManger.getEntityManager(), em);
    }

    /**
     * Method to test createEntity in positive scenario
     * 
     * @throws SQLException
     */
    @Test
    public void testCreateEntity() throws SQLException {
        persistenceManger.createEntity(trustProfileData);
    }

    /**
     * Method to test createEntity in negative scenario
     * 
     * @throws SQLException
     */
    @Test(expected = EntityExistsException.class)
    public void testCreateEntityWithEx() throws SQLException {
        doThrow(new EntityExistsException()).when(em).persist(trustProfileData);
        persistenceManger.createEntity(trustProfileData);
    }

    /**
     * Method to test findEntity in positive scenario
     */
    @Test
    public void testFindEntity() {
        when(em.find(TrustProfileData.class, id)).thenReturn(trustProfileData);
        final TrustProfileData data = persistenceManger.findEntity(TrustProfileData.class, id);
        assertEquals(trustProfileData, data);
    }

    /**
     * Method to test findEntity in negative scenario
     */
    @Test(expected = PersistenceException.class)
    public void testFindEntityWithEx() {
        when(em.find(TrustProfileData.class, id)).thenThrow(new PersistenceException());
        persistenceManger.findEntity(TrustProfileData.class, id);
    }

    /**
     * Method to test findEntity in negative scenario
     */
    @Test
    public void testFindEntityNull() {
        final TrustProfileData data = persistenceManger.findEntity(null, id);
        assertEquals(null, data);
    }

    /**
     * Method to test findEntityByName in positive scenario
     */
    @Test
    public void testFindEntityByName() {

        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);

        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);

        when(typedQuery.getResultList()).thenReturn(trustProfileDataList);
        final TrustProfileData data = persistenceManger.findEntityByName(TrustProfileData.class, name, TrustProfileSetUpData.NAME_PATH);
        assertEquals(trustProfileDataList.get(0), data);
    }

    /**
     * Method to test findEntityByName in negative scenario
     */
    @Test
    public void testFindEntityByNameWithEmpty() {

        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);

        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);

        final List<TrustProfileData> listProfiles = new ArrayList<TrustProfileData>();

        when(typedQuery.getResultList()).thenReturn(listProfiles);
        final TrustProfileData data = persistenceManger.findEntityByName(TrustProfileData.class, "", TrustProfileSetUpData.NAME_PATH);
        assertEquals(null, data);
    }

    /**
     * Method to test findEntityByName in negative scenario
     */
    @Test(expected = PersistenceException.class)
    public void testFindEntityByNameWithEx() {

        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);

        when(em.createQuery(criteriaQuery)).thenThrow(new PersistenceException());

        persistenceManger.findEntityByName(TrustProfileData.class, name, TrustProfileSetUpData.NAME_PATH);
    }

    /**
     * Method to test findEntityByIdAndName in positive scenario
     */
    @Test
    public void testFindEntityByIdAndName() {
        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);

        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);

        when(typedQuery.getResultList()).thenReturn(trustProfileDataList);
        final TrustProfileData data = persistenceManger.findEntityByIdAndName(TrustProfileData.class, id, name, TrustProfileSetUpData.NAME_PATH);
        assertEquals(trustProfileDataList.get(0), data);
    }

    /**
     * Method to test findEntityByIdAndName in negative scenario
     */
    @Test
    public void testFindEntityByIdAndNameWithIdZero() {
        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);

        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);

        final List<TrustProfileData> listProfiles = new ArrayList<TrustProfileData>();

        when(typedQuery.getResultList()).thenReturn(listProfiles);
        final TrustProfileData data = persistenceManger.findEntityByIdAndName(TrustProfileData.class, 0, name, TrustProfileSetUpData.NAME_PATH);
        assertEquals(null, data);
    }

    /**
     * Method to test findEntityByIdAndName in negative scenario
     */
    @Test(expected = PersistenceException.class)
    public void testFindEntityByIdAndNameWithEx() {
        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);

        when(em.createQuery(criteriaQuery)).thenThrow(new PersistenceException());

        persistenceManger.findEntityByIdAndName(TrustProfileData.class, id, name, TrustProfileSetUpData.NAME_PATH);

    }

    /**
     * Method to test getAllEntities in positive scenario
     */
    @Test
    public void testGetAllEntityItems() {

        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);
        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);
        when(typedQuery.getResultList()).thenReturn(trustProfileDataList);
        assertEquals(trustProfileDataList, persistenceManger.getAllEntityItems(TrustProfileData.class));
    }

    /**
     * Method to test getAllEntities in negative scenario
     */
    @Test(expected = PersistenceException.class)
    public void testGetAllEntityItemsWithEx() {

        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);
        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);
        when(typedQuery.getResultList()).thenThrow(new PersistenceException());
        persistenceManger.getAllEntityItems(TrustProfileData.class);
    }

    /**
     * Method to test updateEntity in positive scenario
     */
    @Test
    public void testUpdateEntity() {
        when(em.merge(trustProfileData)).thenReturn(trustProfileData);
        assertEquals(persistenceManger.updateEntity(trustProfileData), trustProfileData);
    }

    /**
     * Method to test updateEntity in negative scenario
     */
    @Test(expected = TransactionRequiredException.class)
    public void testUpdateEntityWithEx() {
        when(em.merge(trustProfileData)).thenThrow(new TransactionRequiredException());
        persistenceManger.updateEntity(trustProfileData);
    }

    /**
     * Method to test refresh in positive scenario
     */
    @Test
    public void testRefreshEntity() {

        persistenceManger.refresh(trustProfileData);
    }

    /**
     * Method to test refresh in negative scenario
     */
    @Test(expected = TransactionRequiredException.class)
    public void testRefreshEntityEx() {
        doThrow(new TransactionRequiredException()).when(em).refresh(trustProfileData);
        persistenceManger.refresh(trustProfileData);
    }

    /**
     * Method to test refresh in negative scenario
     */
    @Test(expected = EntityNotFoundException.class)
    public void testRefreshEntityNotFoundEx() {
        doThrow(new EntityNotFoundException()).when(em).refresh(trustProfileData);
        persistenceManger.refresh(trustProfileData);
    }

    /**
     * Method to test deleteEntity in positive scenario
     */
    @Test
    public void testDeleteEntity() {
        persistenceManger.deleteEntity(trustProfileData);
    }

    /**
     * Method to test deleteEntity in negative scenario
     */
    @Test(expected = TransactionRequiredException.class)
    public void testDeleteEntityWithEx() {
        doThrow(new TransactionRequiredException()).when(em).remove(trustProfileData);
        persistenceManger.deleteEntity(trustProfileData);
    }

    /**
     * Method to test findEntityWhere in positive scenario
     */
    @Test
    public void testFindEntityWhere() {

        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);
        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);

        when(typedQuery.getResultList()).thenReturn(trustProfileDataList);
        final TrustProfileData data = persistenceManger.findEntityWhere(TrustProfileData.class, input);
        assertEquals(trustProfileDataList.get(0), data);
    }

    /**
     * Method to test findEntityWhere in negative scenario
     */
    @Test(expected = PersistenceException.class)
    public void testFindEntityWhereWithEx() {

        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);
        when(em.createQuery(criteriaQuery)).thenThrow(new PersistenceException());

        persistenceManger.findEntityWhere(TrustProfileData.class, input);
    }

    /**
     * Method to test findEntityIn in positive scenario
     */
    @Test
    public void testFindEntityIN() {
        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);
        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);
        when(typedQuery.getResultList()).thenReturn(trustProfileDataList);

        when(root.get(TrustProfileSetUpData.NAME_PATH)).thenReturn(path);
        when(path.in(values)).thenReturn(predicate);
        assertEquals(trustProfileDataList, persistenceManger.findEntityIN(TrustProfileData.class, values, TrustProfileSetUpData.NAME_PATH));
    }

    /**
     * Method to test testFindEntitiesWhere with attributes in positive scenario
     */
    @Test
    public void testFindEntitiesWhere() {

        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);
        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);
        when(typedQuery.getResultList()).thenReturn(trustProfileDataList);

        when(root.get(TrustProfileSetUpData.NAME_PATH)).thenReturn(path);
        when(path.in(values)).thenReturn(predicate);
        assertEquals(trustProfileDataList, persistenceManger.findEntitiesWhere(TrustProfileData.class, input));
    }

    @Test
    public void testFindEntitiesWhereWithoutKey() {
        Map<String, Object> input = new HashMap<String, Object>();
        input.put("key.Path", "hello");
        final StringTokenizer stringTokenizer = new StringTokenizer("key.Path", ".");

        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);
        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);
        when(typedQuery.getResultList()).thenReturn(trustProfileDataList);

        when(root.get(stringTokenizer.nextElement().toString())).thenReturn(path);
        when(root.get(TrustProfileSetUpData.NAME_PATH)).thenReturn(path);
        when(path.in(values)).thenReturn(predicate);
        assertEquals(trustProfileDataList, persistenceManger.findEntitiesWhere(TrustProfileData.class, input));
    }

    /**
     * Method to test findEntityIn in negative scenario
     */
    @Test(expected = PersistenceException.class)
    public void testFindEntityINWithEx() {
        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);
        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);
        when(typedQuery.getResultList()).thenThrow(new PersistenceException());

        when(root.get(TrustProfileSetUpData.NAME_PATH)).thenReturn(path);
        when(path.in(values)).thenReturn(predicate);
        persistenceManger.findEntityIN(TrustProfileData.class, values, TrustProfileSetUpData.NAME_PATH);
    }

    /**
     * Method to test findEntitiesByAttributes in positive scenario
     */
    @Test
    public void testFindEntitiesByAttributesWithClass() {
        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);
        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);
        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);

        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);
        when(typedQuery.getResultList()).thenReturn(trustProfileDataList);

        when(root.get("id")).thenReturn(path);

        assertNotNull(persistenceManger.findEntitiesByAttributes(TrustProfileData.class, input));

    }

    /**
     * Method to test findEntitiesByAttributes in negative scenario
     */
    @Test(expected = PersistenceException.class)
    public void testFindEntitiesByAttributesWithEx() {
        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);
        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);
        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);

        when(em.createQuery(criteriaQuery)).thenThrow(new PersistenceException());

        when(root.get("id")).thenReturn(path);

        persistenceManger.findEntitiesByAttributes(TrustProfileData.class, input);
    }

    /**
     * Method to test findEntitiesByAttributesInputList in positive scenario
     */
    @Test
    public void testFindEntitiesByAttributesInputList() {
        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);
        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);
        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);

        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);
        when(typedQuery.getResultList()).thenReturn(trustProfileDataList);

        when(root.get("listProfile")).thenReturn(path);

        input.put("listProfile", trustProfileDataList);
        persistenceManger.findEntitiesByAttributes(TrustProfileData.class, input);
    }

    /**
     * Method to test findEntitiesByNativeQuery without attributes in positive scenario
     */
    @Test
    public void testFindEntitiesByNativeQuery() {

        final String query = "select c.id as ID,c.publishCertificatetoTDPS,c.name,null as otp,null as otpcount,c.subject_dn,c.subject_alt_name,c.status_id,a.id as algorithm_id,a.key_size,a.name as algorithm_name,a.oid,a.is_supported,a.type_id,p.id as profile_id,p.name as profile_name,true,coalesce(ca_cert.count, 0) as count from caentity c inner join algorithm a on a.id=c.key_generation_algorithm_id inner join entityprofile p on p.id=c.entity_profile_id left join (select ca_id,count(certificate_id) as count from ca_certificate group by ca_id) ca_cert on ca_cert.ca_id=c.id  UNION select e.id as ID,e.publishCertificatetoTDPS,e.name,e.otp,e.otp_count,e.subject_dn,e.subject_alt_name,e.status_id,a.id as algorithm_id,a.key_size,a.name as algorithm_name,a.oid,a.is_supported,a.type_id,p.id as profile_id,p.name as profile_name,false,coalesce(entity_cert.count, 0) as count from entity e inner join algorithm a on a.id=e.key_generation_algorithm_id inner join entityprofile p on p.id=e.entity_profile_id left join (select entity_id,count(certificate_id) as count from entity_certificate group by entity_id) entity_cert on entity_cert.entity_id=e.id  order by ID";

        when(em.createNativeQuery(query)).thenReturn(queryEM);

        final List enititesList = new ArrayList();

        when(queryEM.getResultList()).thenReturn(enititesList);

        final List enititesListExpected = persistenceManger.findEntitiesByNativeQuery(query, 0, 10);

        assertNotNull(enititesListExpected);

    }

    /**
     * Method to test findEntitiesByNativeQuery with attributes in positive scenario
     */
    @Test
    public void testFindEntitiesByNativeQueryWithAttributes() {

        final String query = "select c.id as ID,c.publishCertificatetoTDPS,c.name,null as otp,null as otpcount,c.subject_dn,c.subject_alt_name,c.status_id,a.id as algorithm_id,a.key_size,a.name as algorithm_name,a.oid,a.is_supported,a.type_id,p.id as profile_id,p.name as profile_name,true,coalesce(ca_cert.count, 0) as count from caentity c inner join algorithm a on a.id=c.key_generation_algorithm_id inner join entityprofile p on p.id=c.entity_profile_id left join (select ca_id,count(certificate_id) as count from ca_certificate group by ca_id) ca_cert on ca_cert.ca_id=c.id where c.name like :entityName and c.status_id in (:statusList)  and (select count(certificate_id) from  ca_certificate ca_cert where ca_cert.ca_id=c.id)= :certificateCount UNION select e.id as ID,e.publishCertificatetoTDPS,e.name,e.otp,e.otp_count,e.subject_dn,e.subject_alt_name,e.status_id,a.id as algorithm_id,a.key_size,a.name as algorithm_name,a.oid,a.is_supported,a.type_id,p.id as profile_id,p.name as profile_name,false,coalesce(entity_cert.count, 0) as count from entity e inner join algorithm a on a.id=e.key_generation_algorithm_id inner join entityprofile p on p.id=e.entity_profile_id left join (select entity_id,count(certificate_id) as count from entity_certificate group by entity_id) entity_cert on entity_cert.entity_id=e.id where e.name like :entityName and e.status_id in (:statusList)  and (select count(certificate_id) from  entity_certificate entity_cert where entity_cert.entity_id=e.id)= :certificateCount order by ID";

        when(em.createNativeQuery(query)).thenReturn(queryEM);

        final List enititesList = new ArrayList();

        entitiesFilter = getEntitiesFilter();

        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("entityName", entitiesFilter.getName());
        attributes.put("statusList", getEntityStatusList(entitiesFilter));

        when(queryEM.getResultList()).thenReturn(enititesList);

        final List enititesListExpected = persistenceManger.findEntitiesByNativeQuery(query, attributes, 0, 10);

        assertNotNull(enititesListExpected);

    }

    @Test
    public void testGetEntities() {

        Mockito.when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);
        Mockito.when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);
        Mockito.when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);
        Mockito.when(typedQuery.getResultList()).thenReturn(trustProfileDataList);

        assertEquals(trustProfileDataList, persistenceManger.getEntities(TrustProfileData.class));
    }

    @Test
    public void testGetEntitiesWithOffset() {

        Mockito.when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);
        Mockito.when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);
        Mockito.when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);
        Mockito.when(typedQuery.getResultList()).thenReturn(trustProfileDataList);
        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);

        assertEquals(trustProfileDataList, persistenceManger.getEntities(TrustProfileData.class, 0, 10));
    }

    @Test
    public void testFindEntitiesByAttributesWithQuery() {
        when(em.createQuery(name)).thenReturn(queryEM);

        assertNotNull(persistenceManger.findEntitiesByAttributes(name, input));

        Mockito.verify(em).createQuery(name);
    }

    @Test
    public void testFindEntitiesByAttributesWithOffset() {
        when(em.createQuery(name)).thenReturn(queryEM);

        assertNotNull(persistenceManger.findEntitiesByAttributes(name, input, 0, 10));
    }

    @Test
    public void testFindEntitiesCountByAttributes() {
        when(em.createQuery(name)).thenReturn(queryEM);
        when(queryEM.getSingleResult()).thenReturn(id);
        assertEquals(id, persistenceManger.findEntitiesCountByAttributes(name, input));
    }

    @Test
    public void testGetEntitiesCount() {

        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);
        when(criteriaBuilder.createQuery(Long.class)).thenReturn(criteriaQueryLong);
        when(em.createQuery(criteriaQueryLong)).thenReturn(typedQueryLong);
        when(typedQueryLong.getSingleResult()).thenReturn(id);
        assertEquals(id, persistenceManger.getEntitiesCount(TrustProfile.class));
    }

    @Test
    public void testFindEntitiesByAttributesMap() {
        when(em.createQuery(name)).thenReturn(queryEM);
        assertNotNull(persistenceManger.findEntitiesByAttributes(TrustProfile.class, name, input));
    }

    @Test
    public void testFindEntitiesByNativeQueryWithClass() {
        when(em.createNativeQuery(name, TrustProfile.class)).thenReturn(queryEM);
        when(queryEM.getResultList()).thenReturn(values);
        assertEquals(values, persistenceManger.findEntitiesByNativeQuery(TrustProfile.class, name, input, 0, 10));
    }

    @Test
    public void testFindEntitiesByNativeQueryMap() {
        when(em.createNativeQuery(name)).thenReturn(queryEM);
        when(queryEM.getResultList()).thenReturn(values);
        assertEquals(values, persistenceManger.findEntitiesByNativeQuery(name, input));
    }

    @Test
    public void testFindEntityCountByNativeQueryMap() {
        when(em.createNativeQuery(name)).thenReturn(queryEM);
        when(queryEM.getSingleResult()).thenReturn(name);
        assertEquals(name, persistenceManger.findEntityCountByNativeQuery(name, input));
    }

    @Test
    public void testFindEntitiesByNativeQueryString() {
        when(em.createNativeQuery(name)).thenReturn(queryEM);
        when(queryEM.getResultList()).thenReturn(values);
        assertEquals(values, persistenceManger.findEntitiesByNativeQuery(name));
    }

    @Test
    public void testFindIdsByNativeQuery() {
        when(em.createNativeQuery(name)).thenReturn(queryEM);
        when(queryEM.getResultList()).thenReturn(values);
        assertEquals(values, persistenceManger.findIdsByNativeQuery(name));
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
