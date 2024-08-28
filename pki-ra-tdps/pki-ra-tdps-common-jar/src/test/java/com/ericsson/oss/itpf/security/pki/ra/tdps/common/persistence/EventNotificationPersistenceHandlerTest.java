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
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionServiceException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.constants.Constants;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSCertificateStatus;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSEntity;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity.TDPSEntityData;

@RunWith(MockitoJUnitRunner.class)
public class EventNotificationPersistenceHandlerTest {

    @InjectMocks
    EventNotificationPersistenceHandler eventNotificationPersistenceHandler;

    @Mock
    EntityManager entityManager;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    TDPSEntityData tDPSEntityData;

    @Mock
    Logger logger;

    @Mock
    Query query;

    @Mock
    EntityTransaction transaction;

    private String entityName = "end_entity";
    private String serialNo = "01sd345t456";
    private String issuerName = "rootCA";

    @Test
    public void testPersistTDPSResponse() {

        setupData();

        List<TDPSEntityData> entitiesList = new ArrayList<TDPSEntityData>();
        entitiesList.add(tDPSEntityData);

        setEntityData();

        Mockito.when(
                entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType").setParameter(Constants.ENTITY_NAME_PARAM, tDPSEntityData.getEntityName())
                        .setParameter(Constants.ENTITY_TYPE_PARAM, tDPSEntityData.getEntityType()).setParameter(Constants.CERTIFICATE_SERIAL_ID_PARAM, tDPSEntityData.getSerialNo())
                        .setParameter(Constants.CERTIFICATE_STATUS_PARAM, tDPSEntityData.getTdpsCertificateStatus()).setParameter(Constants.ISSUER_NAME_PARAM, tDPSEntityData.getIssuerName())
                        .getSingleResult()).thenReturn(tDPSEntityData);

        eventNotificationPersistenceHandler.persistTdpsEntities(entitiesList);
    }

    @Test
    public void testPersistTDPSResponseNull() {
        setupData();

        List<TDPSEntityData> entitiesList = new ArrayList<TDPSEntityData>();
        entitiesList.add(tDPSEntityData);

        setEntityData();

        Mockito.when(
                entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType").setParameter(Constants.ENTITY_NAME_PARAM, tDPSEntityData.getEntityName())
                        .setParameter(Constants.ENTITY_TYPE_PARAM, tDPSEntityData.getEntityType()).setParameter(Constants.CERTIFICATE_SERIAL_ID_PARAM, tDPSEntityData.getSerialNo())
                        .setParameter(Constants.CERTIFICATE_STATUS_PARAM, tDPSEntityData.getTdpsCertificateStatus()).setParameter(Constants.ISSUER_NAME_PARAM, tDPSEntityData.getIssuerName())
                        .getSingleResult()).thenReturn(null);

        eventNotificationPersistenceHandler.persistTdpsEntities(entitiesList);
    }

    @Test(expected = TrustDistributionServiceException.class)
    public void testPersistTDPSResponsePersistenceException() {

        Mockito.doThrow(new PersistenceException()).when(persistenceManager).getEntityManager();
        List<TDPSEntityData> entitiesList = new ArrayList<TDPSEntityData>();
        entitiesList.add(tDPSEntityData);
        eventNotificationPersistenceHandler.persistTdpsEntities(entitiesList);
    }

    private void setEntityData() {
        Mockito.when(tDPSEntityData.getEntityName()).thenReturn(entityName);
        Mockito.when(tDPSEntityData.getEntityType()).thenReturn(TDPSEntity.ENTITY);
        Mockito.when(tDPSEntityData.getSerialNo()).thenReturn(serialNo);
        Mockito.when(tDPSEntityData.getTdpsCertificateStatus()).thenReturn(TDPSCertificateStatus.ACTIVE);
        Mockito.when(tDPSEntityData.getIssuerName()).thenReturn(issuerName);

        Mockito.when(entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType")).thenReturn(query);

        Mockito.when(entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType").setParameter(Constants.ENTITY_NAME_PARAM, tDPSEntityData.getEntityName())).thenReturn(query);

        Mockito.when(
                entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType").setParameter(Constants.ENTITY_NAME_PARAM, tDPSEntityData.getEntityName())
                        .setParameter(Constants.ENTITY_TYPE_PARAM, tDPSEntityData.getEntityType())).thenReturn(query);

        Mockito.when(
                entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType").setParameter(Constants.ENTITY_NAME_PARAM, tDPSEntityData.getEntityName())
                        .setParameter(Constants.ENTITY_TYPE_PARAM, tDPSEntityData.getEntityType()).setParameter(Constants.CERTIFICATE_SERIAL_ID_PARAM, tDPSEntityData.getSerialNo())).thenReturn(query);

        Mockito.when(
                entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType").setParameter(Constants.ENTITY_NAME_PARAM, tDPSEntityData.getEntityName())
                        .setParameter(Constants.ENTITY_TYPE_PARAM, tDPSEntityData.getEntityType()).setParameter(Constants.CERTIFICATE_SERIAL_ID_PARAM, tDPSEntityData.getSerialNo())
                        .setParameter(Constants.CERTIFICATE_STATUS_PARAM, tDPSEntityData.getTdpsCertificateStatus())).thenReturn(query);

        Mockito.when(
                entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType").setParameter(Constants.ENTITY_NAME_PARAM, tDPSEntityData.getEntityName())
                        .setParameter(Constants.ENTITY_TYPE_PARAM, tDPSEntityData.getEntityType()).setParameter(Constants.CERTIFICATE_SERIAL_ID_PARAM, tDPSEntityData.getSerialNo())
                        .setParameter(Constants.CERTIFICATE_STATUS_PARAM, tDPSEntityData.getTdpsCertificateStatus()).setParameter(Constants.ISSUER_NAME_PARAM, tDPSEntityData.getIssuerName()))
                .thenReturn(query);
    }

    private void setupData() {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
    }

}