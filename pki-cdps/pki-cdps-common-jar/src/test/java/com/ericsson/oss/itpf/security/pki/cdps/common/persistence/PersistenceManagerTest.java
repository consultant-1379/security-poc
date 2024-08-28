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
package com.ericsson.oss.itpf.security.pki.cdps.common.persistence;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.*;

import javax.persistence.*;
import javax.persistence.criteria.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.cdps.common.SetUpData;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData;

/**
 * This class used to test PersistenceManager functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class PersistenceManagerTest extends SetUpData {

    @InjectMocks
    PersistenceManager persistenceManager;

    @Mock
    private Logger logger;

    @Mock
    EntityManager entityManager;

    @Mock
    CriteriaBuilder criteriaBuilder;

    @Mock
    CriteriaQuery<CDPSEntityData> criteriaQuery;

    @Mock
    Expression<String> fieldExpression;

    @Mock
    Root<CDPSEntityData> entity;

    @Mock
    List<Predicate> predicatesList;

    @Mock
    Predicate predicate;

    @Mock
    TypedQuery<CDPSEntityData> query;

    @Mock
    Path<Object> path;

    Expression<String> expression;

    private Map<String, Object> input;
    private List<CDPSEntityData> list_return;
    private List<CDPSEntityData> Objects;
    private EntityManager entityManager_retun;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        input = new HashMap<String, Object>();
        input.put("caName", "nu_oam_ca");
        input.put("CertSerialNumber", "204173BB72886E4B1CB6700267AA3B3D");

        Objects = new LinkedList<CDPSEntityData>();
        Objects.add(prepareCDPSEntityData());
        Objects.add(prepareCDPSEntyData());

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.common.persistence.PersistenceManager#getEntityManager()}.
     */
    @Test
    public void testGetEntityManager() {

        entityManager_retun = persistenceManager.getEntityManager();

        assertNotNull(entityManager_retun);
        assertEquals(entityManager, entityManager_retun);

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.common.persistence.PersistenceManager#findEntitiesWhere(java.lang.Class, java.util.Map)}.
     */
    @Test
    public void testFindEntitiesWhere() {

        Mockito.when(entityManager.getCriteriaBuilder()).thenReturn(criteriaBuilder);
        Mockito.when(criteriaBuilder.createQuery(CDPSEntityData.class)).thenReturn(criteriaQuery);
        Mockito.when(criteriaQuery.from(CDPSEntityData.class)).thenReturn(entity);
        Mockito.when(entityManager.createQuery(criteriaQuery)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Objects);

        list_return = persistenceManager.findEntitiesWhere(CDPSEntityData.class, input);

        assertNotNull(list_return);
        assertEquals(input.get("caName"), list_return.get(0).getCaName());
        assertEquals(input.get("CertSerialNumber"), list_return.get(0).getCertSerialNumber());

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.common.persistence.PersistenceManager#findEntitiesWhere(java.lang.Class, java.util.Map)}.
     */
    @Test(expected = PersistenceException.class)
    public void testFindEntitiesWhereThrowsPersistenceException() {

        Mockito.when(criteriaBuilder.createQuery(CDPSEntityData.class)).thenReturn(criteriaQuery);
        Mockito.when(entityManager.getCriteriaBuilder()).thenReturn(criteriaBuilder);
        Mockito.when(criteriaQuery.from(CDPSEntityData.class)).thenReturn(entity);
        Mockito.when(entityManager.createQuery(criteriaQuery)).thenReturn(query);
        Mockito.when(query.getResultList()).thenThrow(new PersistenceException());

        persistenceManager.findEntitiesWhere(CDPSEntityData.class, input);

    }

}
