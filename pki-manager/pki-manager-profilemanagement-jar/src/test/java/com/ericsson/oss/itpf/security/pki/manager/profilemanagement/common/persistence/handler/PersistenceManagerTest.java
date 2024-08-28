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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.persistence.handler;

import static org.junit.Assert.assertEquals;
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

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data.TrustProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class PersistenceManagerTest {

    /**
     * 
     */
    private static final String NATIVE_QUERY = "select id,name from caentity where status_id= :status_id";

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
    private Root<TrustProfileData> root;

    @Mock
    private Predicate predicate;

    @Mock
    private TypedQuery<TrustProfileData> typedQuery;

    @Mock
    private Path<Object> path;

    @Mock
    private Query query;

    private List<TrustProfileData> trustProfileDataList;
    private TrustProfileData trustProfileData;
    private List<String> values;
    private Map<String, Object> input;

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
        Mockito.when(em.find(TrustProfileData.class, id)).thenThrow(new PersistenceException());
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
        assertEquals(trustProfileDataList, persistenceManger.getEntities(TrustProfileData.class));
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
        persistenceManger.getEntities(TrustProfileData.class);
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
    public void testFindEntitiesByAttributes() {
        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);
        when(criteriaBuilder.createQuery(TrustProfileData.class)).thenReturn(criteriaQuery);
        when(criteriaQuery.from(TrustProfileData.class)).thenReturn(root);

        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);
        when(typedQuery.getResultList()).thenReturn(trustProfileDataList);

        when(root.get("id")).thenReturn(path);

        persistenceManger.findEntitiesByAttributes(TrustProfileData.class, input);
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
     * Method to test findEntitiesByAttributesInputList in positive scenario
     */
    @Test
    public void testFetchEntitiesByNativeQuery() {
        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("status_id", CAStatus.ACTIVE.getId());

        when(em.createNativeQuery(NATIVE_QUERY)).thenReturn(query);

        final List<Object[]> objects = new ArrayList<Object[]>();
        when(query.getResultList()).thenReturn(objects);

        final List<Object[]> objects_1 = persistenceManger.findEntitiesByNativeQuery(NATIVE_QUERY, attributes);
        assertEquals(objects, objects_1);
    }
}
