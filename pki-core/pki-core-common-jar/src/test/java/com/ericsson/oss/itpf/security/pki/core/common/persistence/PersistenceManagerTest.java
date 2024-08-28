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
package com.ericsson.oss.itpf.security.pki.core.common.persistence;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.*;

import javax.persistence.*;
import javax.persistence.criteria.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class PersistenceManagerTest {

    @InjectMocks
    PersistenceManager persistenceManger;

    @Mock
    EntityManager em;

    @Mock
    Query query;

    @Mock
    CriteriaBuilder criteriaBuilder;

    @Mock
    CriteriaQuery<CertificateAuthorityData> criteriaQuery;

    @Mock
    Root<CertificateAuthorityData> root;

    @Mock
    Predicate predicate;

    @Mock
    TypedQuery<CertificateAuthorityData> typedQuery;

    @Mock
    Path<Object> path;

    @Mock
    Logger logger;

    private CertificateAuthorityData certificateAuthorityData;
    Map<String, Object> input = new HashMap<String, Object>();
    List<CertificateAuthorityData> certificateAuthorityDatas = new ArrayList<CertificateAuthorityData>();

    private CertificateData certificateData;

    private final static String cAName = "ENM_RootCA";
    private final static String namePath = "name";
    private final static long id = 1;

    /**
     * Prepares initial data.
     * 
     * @throws CertificateEncodingException
     * @throws CertificateException
     * @throws IOException
     */
    @Before
    public void setUp() throws CertificateEncodingException, CertificateException, IOException {

        certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName(cAName);
        certificateAuthorityData.setSubjectDN("CN=ERBS, OU=Ericsson, O=ENM");
        certificateAuthorityData.setId(id);
        certificateAuthorityDatas.add(certificateAuthorityData);
        input.put("id", 1);

        certificateData = new CertificateData();
        certificateData.setId(Long.valueOf(1));
    }

    /**
     * Method to test create entity in the database.
     */
    @Test
    public void testCreateEntity() {

        persistenceManger.createEntity(certificateAuthorityData);
    }

    /**
     * Method to test update entity in the database.
     */
    @Test
    public void testUpdateEntity() {

        persistenceManger.updateEntity(certificateAuthorityData);
    }

    /**
     * Method to test refresh entity in the persistence cache.
     */
    @Test
    public void testRefreshEntity() {

        persistenceManger.refresh(certificateAuthorityData);
    }

    /**
     * Method to test findEntity in positive scenario
     */
    @Test
    public void testFindEntity() {
        when(em.find(CertificateAuthorityData.class, id)).thenReturn(certificateAuthorityData);
        final CertificateAuthorityData data = persistenceManger.findEntity(CertificateAuthorityData.class, id);
        assertEquals(certificateAuthorityData, data);
    }

    /**
     * Method to test findEntity in negative scenario
     */
    @Test
    public void testFindEntityNull() {
        final CertificateAuthorityData data = persistenceManger.findEntity(null, id);
        assertEquals(null, data);
    }

    /**
     * Method to test find entity in the database, with the given attributes.
     */
    @Test
    public void testFindEntitiesByAttributes() {

        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);
        when(criteriaBuilder.createQuery(CertificateAuthorityData.class)).thenReturn(criteriaQuery);
        when(criteriaQuery.from(CertificateAuthorityData.class)).thenReturn(root);

        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);
        when(typedQuery.getResultList()).thenReturn(certificateAuthorityDatas);

        when(root.get("id")).thenReturn(path);

        persistenceManger.findEntitiesByAttributes(CertificateAuthorityData.class, input);
    }

    /**
     * Method to test deleteEntity in positive scenario
     */
    @Test
    public void testDeleteEntity() {
        persistenceManger.deleteEntity(certificateAuthorityData);
    }

    /**
     * Method to test find entity in the database, with the list of attributes.
     */
    @Test
    public void testFindEntitiesByAttributes_WithListAsInput() {

        input.clear();
        final List<Integer> ids = new ArrayList<Integer>();
        ids.add(1);
        input.put("id", ids);

        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);
        when(criteriaBuilder.createQuery(CertificateAuthorityData.class)).thenReturn(criteriaQuery);
        when(criteriaQuery.from(CertificateAuthorityData.class)).thenReturn(root);

        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);
        when(typedQuery.getResultList()).thenReturn(certificateAuthorityDatas);

        when(root.get("id")).thenReturn(path);

        persistenceManger.findEntitiesByAttributes(CertificateAuthorityData.class, input);
    }

    /**
     * Method to test findEntityByName in positive scenario
     */
    @Test
    public void testFindEntityByName() {

        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(CertificateAuthorityData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(CertificateAuthorityData.class)).thenReturn(root);

        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);

        when(typedQuery.getResultList()).thenReturn(certificateAuthorityDatas);
        final CertificateAuthorityData data = persistenceManger.findEntityByName(CertificateAuthorityData.class, certificateAuthorityData.getName(), namePath);
        assertEquals(certificateAuthorityDatas.get(0), data);
    }

    /**
     * Method to test findEntityByName in negative scenario
     */
    @Test
    public void testFindEntityByNameWithEmpty() {

        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(CertificateAuthorityData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(CertificateAuthorityData.class)).thenReturn(root);

        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);

        final List<CertificateAuthorityData> certificateAuthorityDatas = new ArrayList<CertificateAuthorityData>();

        when(typedQuery.getResultList()).thenReturn(certificateAuthorityDatas);
        final CertificateAuthorityData data = persistenceManger.findEntityByName(CertificateAuthorityData.class, "", namePath);
        assertEquals(null, data);
    }

    /**
     * Method to test findEntityByIdAndName in positive scenario
     */
    @Test
    public void testFindEntityByIdAndName() {
        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(CertificateAuthorityData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(CertificateAuthorityData.class)).thenReturn(root);

        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);

        when(typedQuery.getResultList()).thenReturn(certificateAuthorityDatas);
        final CertificateAuthorityData data = persistenceManger.findEntityByIdAndName(CertificateAuthorityData.class, id, cAName, namePath);
        assertEquals(certificateAuthorityDatas.get(0), data);
    }

    /**
     * Method to test findEntityByIdAndName in negative scenario
     */
    @Test
    public void testFindEntityByIdAndNameWithIdZero() {
        when(em.getCriteriaBuilder()).thenReturn(criteriaBuilder);

        when(criteriaBuilder.createQuery(CertificateAuthorityData.class)).thenReturn(criteriaQuery);

        when(criteriaQuery.from(CertificateAuthorityData.class)).thenReturn(root);

        when(em.createQuery(criteriaQuery)).thenReturn(typedQuery);

        final List<CertificateAuthorityData> certificateAuthorityDatas = new ArrayList<CertificateAuthorityData>();

        when(typedQuery.getResultList()).thenReturn(certificateAuthorityDatas);
        final CertificateAuthorityData data = persistenceManger.findEntityByIdAndName(CertificateAuthorityData.class, 0, cAName, namePath);
        assertEquals(null, data);
    }

    @Test
    public void testupdateEntity() {
        when(em.createQuery("update CertificateData set status = :status_id where id = :id")).thenReturn(typedQuery);
        persistenceManger.updateEntity(certificateData);
    }
}
