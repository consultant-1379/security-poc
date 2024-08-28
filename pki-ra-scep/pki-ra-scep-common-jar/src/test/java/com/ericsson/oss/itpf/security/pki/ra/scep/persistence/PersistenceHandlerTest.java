/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.scep.persistence;

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

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.scep.constants.ResponseStatus;
import com.ericsson.oss.itpf.security.pki.common.scep.model.ScepResponse;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.entity.Pkcs7ScepRequestEntity;

/**
 * This class Test PersistanceHandler
 */
@SuppressWarnings("rawtypes")
@RunWith(MockitoJUnitRunner.class)
public class PersistenceHandlerTest {

    @InjectMocks
    private PersistenceHandler peristanceHandler;

    @Mock
    private EntityManager entityManager;

    @Mock
    private CriteriaQuery criteriaQuery;

    @Mock
    private CriteriaBuilder criteriaBuilder;

    @Mock
    private Root entity;

    @Mock
    private TypedQuery typedQuery;

    @Mock
    private Query query;

    @Mock
    private Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    private ScepResponse scepResponse;

    private Pkcs7ScepRequestEntity pkcs7RequestEntity;

    final private String transactionId = "33D29237707C1B0B937D563EE093BA1EDF981D3A";
    final private String subjectDN = "CN=atclvm1022:lienb0511_cus_ipsec";
    final private String issuerDN = "O=Ericsson,CN=LTEIPSecNEcusRootCA";
    final private String failureInfo = "test";
    final private int status = ResponseStatus.SUCCESS.getStatus();
    final private byte[] certificate = new byte[10];
    final private String searchEnrityExpectedLog = "End of searchEntitiesByAttributes method in PersistanceHandler class ";
    final private String persistPkcsExpectedLog = "persistPkcs7ScepRequestEntity method in PersistanceHandler class ";
    final private String updatePkcsExpectedLog = "updatePkcs7ScepRequestEntity method in ResponseProcessor class  ";
    final private String deleteOldRecordsFromScepDbDebugLog = "End of the method deleteRecordsFromScepDb of class PersistenceHandler";
    final private String deleteOldRecordsFromScepDbErrorLog = "Error occured while Database cleanup process {} ";
    final private int purgePeriod = 12;

    @Before
    public void setUp() {
        pkcs7RequestEntity = new Pkcs7ScepRequestEntity();
        pkcs7RequestEntity.setTransactionid(transactionId);
        pkcs7RequestEntity.setStatus(ResponseStatus.SUCCESS.getStatus());
    }

    /**
     * This method tests searchEntities based on the parameters
     */
    @Test
    public void testSearchEntitiesByAttributes() {
        mockEnityManagerCalls();

        final HashMap<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("transactionId", transactionId);
        parameters.put("subjectDN", subjectDN);
        parameters.put("issuerDN", issuerDN);
        List<Pkcs7ScepRequestEntity> pkcs7ScepRequestEntityList = peristanceHandler.searchEntitiesByAttributes(Pkcs7ScepRequestEntity.class, parameters);
        Mockito.verify(logger).debug(searchEnrityExpectedLog);
        assertNotNull(pkcs7ScepRequestEntityList);
    }

    /**
     * This method tests searchEntities based on the parameters
     */
    @Test
    public void testSearchEntitiesByAttributes_WithEntity_ReturnsResultList() {
        mockEnityManagerCalls();

        Mockito.when(entity.get(Mockito.anyString())).thenReturn(entity);

        final HashMap<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("transactionId", transactionId);
        parameters.put("subjectDN", subjectDN);
        parameters.put("issuerDN", issuerDN);
        List<Pkcs7ScepRequestEntity> pkcs7ScepRequestEntityList = peristanceHandler.searchEntitiesByAttributes(Pkcs7ScepRequestEntity.class, parameters);
        Mockito.verify(logger).debug(searchEnrityExpectedLog);
        assertNotNull(pkcs7ScepRequestEntityList);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testSearchEntitiesByAttributes_ListOfEntities_ReturnsResultList() {
        mockEnityManagerCalls();
        Mockito.when(entity.get(Mockito.anyString())).thenReturn(entity);

        final HashMap<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("transactionId", transactionId);
        List list = new LinkedList<String>();
        list.add(subjectDN);
        parameters.put("subjectDN", list);
        parameters.put("issuerDN", issuerDN);
        List<Pkcs7ScepRequestEntity> pkcs7ScepRequestEntityList = peristanceHandler.searchEntitiesByAttributes(Pkcs7ScepRequestEntity.class, parameters);
        Mockito.verify(logger).debug(searchEnrityExpectedLog);
        assertNotNull(pkcs7ScepRequestEntityList);
    }

    /**
     * This method will store pkcs7RequestEntity entity into database.
     */
    @Test
    public void testPersistPkcs7ScepRequestEntity() {
        peristanceHandler.persistPkcs7ScepRequestEntity(pkcs7RequestEntity);
        Mockito.verify(logger).debug(persistPkcsExpectedLog);
    }

    /**
     * This method will update pkcs7RequestEntity
     */
    @Test
    public void testupdatePkcs7ScepRequestEntity() {
        Mockito.when(entityManager.createQuery((String) Mockito.anyObject())).thenReturn(query);
        peristanceHandler.updatePkcs7ScepRequestEntity(pkcs7RequestEntity);

        Mockito.verify(logger).debug(updatePkcsExpectedLog);
    }

    @Test
    public void testUpdateSCEPResponseStatus() {
        Mockito.when(entityManager.find(Pkcs7ScepRequestEntity.class, transactionId)).thenReturn(pkcs7RequestEntity);
        Mockito.when(scepResponse.getFailureInfo()).thenReturn(failureInfo);
        Mockito.when(scepResponse.getCertificate()).thenReturn(certificate);
        Mockito.when(scepResponse.getStatus()).thenReturn(status);
        Mockito.when(scepResponse.getTransactionId()).thenReturn(transactionId);

        peristanceHandler.updateSCEPResponseStatus(scepResponse);

        Mockito.verify(logger).debug(updatePkcsExpectedLog);
    }

    @Test
    public void testDeleteOldRecordsFromScepDb_FailureScenario() {

        peristanceHandler.deleteOldRecordsFromScepDb(purgePeriod);
        Mockito.verify(logger).error(deleteOldRecordsFromScepDbErrorLog, new NullPointerException().getMessage());
        Mockito.verify(logger).debug(deleteOldRecordsFromScepDbDebugLog);
    }

    @Test
    public void testDeleteOldRecordsFromScepDb_SuccessScenario() {

        Mockito.when(entityManager.createNamedQuery("Pkcs7ScepRequestEntity.deleteEntity")).thenReturn(query);
        Mockito.when(query.setParameter(Mockito.anyString(), Mockito.anyObject())).thenReturn(query);
        peristanceHandler.deleteOldRecordsFromScepDb(purgePeriod);
        Mockito.verify(logger).debug(deleteOldRecordsFromScepDbDebugLog);
    }

    @SuppressWarnings("unchecked")
    public void mockEnityManagerCalls() {
        Mockito.when(entityManager.find(Pkcs7ScepRequestEntity.class, transactionId)).thenReturn(pkcs7RequestEntity);
        Mockito.when(criteriaBuilder.createQuery((Class) Mockito.anyObject())).thenReturn(criteriaQuery);
        Mockito.when(entityManager.getCriteriaBuilder()).thenReturn(criteriaBuilder);
        Mockito.when(criteriaQuery.from((Class) Mockito.anyObject())).thenReturn(entity);
        Mockito.when(entityManager.createQuery(criteriaQuery)).thenReturn(typedQuery);
        peristanceHandler.persistPkcs7ScepRequestEntity(pkcs7RequestEntity);
        Mockito.when(entityManager.createQuery((String) Mockito.anyObject())).thenReturn(query);
    }

}