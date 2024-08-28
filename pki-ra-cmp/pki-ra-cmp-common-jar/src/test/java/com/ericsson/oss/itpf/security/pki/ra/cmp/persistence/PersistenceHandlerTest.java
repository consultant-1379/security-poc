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

package com.ericsson.oss.itpf.security.pki.ra.cmp.persistence;

import static org.mockito.Mockito.times;

import java.io.IOException;
import java.util.*;

import javax.persistence.*;
import javax.persistence.criteria.*;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.CMPRequestType;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.common.util.DateUtility;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;

@RunWith(MockitoJUnitRunner.class)
public class PersistenceHandlerTest {

    @InjectMocks
    PersistenceHandler persistenceHandler;

    @Mock
    static EntityManager entityManager;

    @Mock
    Query query;

    @Mock
    Logger logger;

    @Mock
    CMPMessageEntity protocolMessageEntity;

    @Mock
    CriteriaBuilder criteriaBuilder;

    @Mock
    CriteriaQuery<CMPMessageEntity> criteriaQuery;

    @Mock
    Root<CMPMessageEntity> cmpMessageEntity;

    @Mock
    TypedQuery<CMPMessageEntity> queryValue;

    @Mock
    TypedQuery<CMPMessageEntity> setStatus;

    @Mock
    TypedQuery<CMPMessageEntity> setRequest;

    @Mock
    TypedQuery<CMPMessageEntity> setRequestType;

    @Mock
    ConfigurationParamsListener configurationParamsListener;

    private static RequestMessage pKIRequestMessage;
    private static String transactionID;
    private static String senderName;

    @BeforeClass
    public static void prepareInitialRequestMessage() throws IOException {

        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);
        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());

        transactionID = pKIRequestMessage.getBase64TransactionID();
        senderName = pKIRequestMessage.getSenderName();
    }

    @Test
    public void testFetchStatusByTransactionID() throws Exception {

        persistenceHandler.fetchStatusByTransactionID(transactionID);

        Mockito.verify(entityManager).find(CMPMessageEntity.class, transactionID);

    }

    @Test
    public void testFetchStatusByTransactionIDNull() throws Exception {

        Mockito.when(entityManager.find(CMPMessageEntity.class, transactionID)).thenReturn(protocolMessageEntity);
        protocolMessageEntity.setStatus(MessageStatus.NEW);
        persistenceHandler.fetchStatusByTransactionID(transactionID);

        Mockito.verify(entityManager).find(CMPMessageEntity.class, transactionID);

    }

    @Test
    public void testFetchEntityByTransactionIdAndEntityName() {

        setUpTestData();

        persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
        Mockito.verify(entityManager, times(2)).createNamedQuery(Matchers.anyString());

    }

    @Test
    public void testUpdateEntity() {
        persistenceHandler.updateEntity(protocolMessageEntity);

        Assert.assertNotNull(protocolMessageEntity);
    }

    @Test
    public void testPersist() {

        persistenceHandler.persist(pKIRequestMessage, transactionID);

        Mockito.verify(logger).info("Saving :{} into DB", pKIRequestMessage.getRequestMessage());

    }

    @Test
    public void testUpdateStatusToRevoke() {
        final List<CMPMessageEntity> entityList = getMockEntityList();

        persistenceHandler.updateEntityStatus(protocolMessageEntity, MessageStatus.FAILED);

        Mockito.verify(protocolMessageEntity).setStatus(MessageStatus.FAILED);
    }

    @Test
    public void testFetchMessageEntitiesBasedOnStatus() {
        setUpTestData();

        persistenceHandler.fetchMessageEntitiesBasedOnStatus(MessageStatus.DONE);

        Mockito.verify(entityManager).createNamedQuery(Matchers.anyString());
    }

    @Test
    public void testFetchMessageEntitiesBasedOnStatusAndReqType() {
        setUpTestData();

        persistenceHandler.fetchMessageEntitiesBasedOnStatusAndReqType(MessageStatus.DONE, CMPRequestType.INITIALIZATION_REQUEST);

        Mockito.verify(entityManager).createNamedQuery(Matchers.anyString());
    }

    private void setUpTestData() {
        Mockito.when(entityManager.getCriteriaBuilder()).thenReturn(criteriaBuilder);
        Mockito.when(criteriaBuilder.createQuery(CMPMessageEntity.class)).thenReturn(criteriaQuery);
        Mockito.when(criteriaQuery.from(CMPMessageEntity.class)).thenReturn(cmpMessageEntity);
        Mockito.when(entityManager.createQuery(criteriaQuery)).thenReturn(queryValue);
        Mockito.when(query.getSingleResult()).thenReturn(protocolMessageEntity);
        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findByStatusAndRequestType")).thenReturn(queryValue);
        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findByStatus")).thenReturn(queryValue);
        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findBySenderNameAndTransactionId")).thenReturn(queryValue);
        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findByStatusAndRequestType")).thenReturn(queryValue);
        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findByTransactionId")).thenReturn(queryValue);
        Mockito.when(queryValue.setParameter("senderName", senderName)).thenReturn(setStatus);
        Mockito.when(setStatus.setParameter("transactionID", transactionID)).thenReturn(setRequest);
        Mockito.when(queryValue.setParameter("status", MessageStatus.DONE)).thenReturn(setStatus);
        Mockito.when(queryValue.setParameter("transactionID", transactionID)).thenReturn(setRequest);
        Mockito.when(setStatus.setParameter("requestType", CMPRequestType.INITIALIZATION_REQUEST)).thenReturn(setRequest);
        Mockito.when(setStatus.setParameter("requestType", CMPRequestType.INITIALIZATION_REQUEST.toString())).thenReturn(setRequest);
        Mockito.when(setRequest.getResultList()).thenReturn(Matchers.anyList());
        // Mockito.when(queryValue.getResultList()).thenReturn(Matchers.anyList());
    }

    private List<CMPMessageEntity> getMockEntityList() {
        final List<CMPMessageEntity> entityList = new ArrayList<CMPMessageEntity>();
        entityList.add(protocolMessageEntity);
        final Date value = DateUtility.getUTCTime();
        Mockito.when(protocolMessageEntity.getModifyTime()).thenReturn(value);
        return entityList;
    }

    @Test
    public void testFetchSenderNameByTransactionID() {
        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findByTransactionId")).thenReturn(queryValue);
        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findByTransactionId").setParameter("transactionID", transactionID)).thenReturn(queryValue);
        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findByTransactionId").setParameter("transactionID", transactionID).getSingleResult()).thenReturn(protocolMessageEntity);

        persistenceHandler.fetchSenderNameByTransactionID(transactionID);

    }

    @Test
    public void testFetchSenderNameByTransactionIDNoResultException() {
        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findByTransactionId")).thenReturn(queryValue);
        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findByTransactionId").setParameter("transactionID", transactionID)).thenReturn(queryValue);
        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findByTransactionId").setParameter("transactionID", transactionID).getSingleResult()).thenReturn(protocolMessageEntity);

        persistenceHandler.fetchSenderNameByTransactionID(transactionID);

    }

    @Test
    public void testUpdateCMPTransactionStatus() {
        byte[] signedResponse = { 2, 5, -5, 8 };
        List<CMPMessageEntity> entities = new ArrayList<CMPMessageEntity>();
        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findByTransactionId")).thenReturn(queryValue);
        Mockito.when(queryValue.setParameter("transactionID", transactionID)).thenReturn(setRequest);

        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findBySenderNameAndTransactionId")).thenReturn(queryValue);
        Mockito.when(queryValue.setParameter("senderName", senderName)).thenReturn(setStatus);
        Mockito.when(setStatus.setParameter("transactionID", transactionID)).thenReturn(setRequest);
        entities.add(protocolMessageEntity);
        Mockito.when(setRequest.getResultList()).thenReturn(entities);

        persistenceHandler.updateCMPTransactionStatus(transactionID, senderName, signedResponse, MessageStatus.DONE);
        Mockito.verify(entityManager).createNamedQuery(Matchers.anyString());
    }

    @Test
    public void testFetchEntityByTransactionID() {
        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findByTransactionId")).thenReturn(queryValue);
        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findByTransactionId").setParameter("transactionID", transactionID)).thenReturn(queryValue);
        persistenceHandler.fetchEntityByTransactionID(transactionID);

    }

    @Test
    public void testUpdateCMPTransactionStatusSenderNonce() {
        byte[] signedResponse = { 2, 5, -5, 8 };
        List<CMPMessageEntity> entities = new ArrayList<CMPMessageEntity>();
        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findByTransactionId")).thenReturn(queryValue);
        Mockito.when(queryValue.setParameter("transactionID", transactionID)).thenReturn(setRequest);
        Mockito.when(entityManager.createNamedQuery("CMPMessageEntity.findBySenderNameAndTransactionId")).thenReturn(queryValue);
        Mockito.when(queryValue.setParameter("senderName", senderName)).thenReturn(setStatus);
        Mockito.when(setStatus.setParameter("transactionID", transactionID)).thenReturn(setRequest);
        entities.add(protocolMessageEntity);
        Mockito.when(setRequest.getResultList()).thenReturn(entities);

        persistenceHandler.updateCMPTransactionStatus(transactionID, senderName, signedResponse, MessageStatus.DONE, "senderNonce");
        Mockito.verify(entityManager).createNamedQuery(Matchers.anyString());
    }

}
