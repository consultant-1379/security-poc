/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence;

import java.util.List;

import javax.persistence.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.tdps.common.constants.Constants;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSCertificateStatus;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSEntity;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.DataLookupException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity.TDPSEntityData;

@RunWith(MockitoJUnitRunner.class)
public class PersistenceManagerTest {

    @InjectMocks
    PersistenceManager persistenceManager;

    @Mock
    EntityManager entityManager;

    @Mock
    Query query;

    @Mock
    List<TDPSEntityData> tDPSEntityData;

    @Mock
    TDPSEntityData tdpsEntity;

    @Mock
    Logger logger;

    private static String entityType = TDPSEntity.ENTITY + "";
    private static String entityName = "name";
    private static String serialNo = "1";
    private static String certificateStatus = TDPSCertificateStatus.ACTIVE + "";
    private static String certificateSerialID = "certificateSerialID";
    private static String issuerName = "issuerName";
    private static final String STRING_FORMATTER = "for EntityName: " + "%s" + " of entity type: " + "%s" + " having " + "%s" + " certificate with serial Id as " + "%s" + " issued by CA " + "%s";

    @Test
    public void testGetCertificate() {

        Mockito.when(entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType")).thenReturn(query);

        Mockito.when(query.setParameter(Constants.ENTITY_NAME_PARAM, entityName)).thenReturn(query);
        Mockito.when(query.setParameter(Constants.ENTITY_NAME_PARAM, entityName).setParameter(Constants.ENTITY_TYPE_PARAM, TDPSEntity.valueOf(entityType.toUpperCase()))).thenReturn(query);
        Mockito.when(
                query.setParameter(Constants.ENTITY_NAME_PARAM, entityName).setParameter(Constants.ENTITY_TYPE_PARAM, TDPSEntity.valueOf(entityType.toUpperCase()))
                        .setParameter(Constants.CERTIFICATE_SERIAL_ID_PARAM, certificateSerialID)).thenReturn(query);
        Mockito.when(
                query.setParameter(Constants.ENTITY_NAME_PARAM, entityName).setParameter(Constants.ENTITY_TYPE_PARAM, TDPSEntity.valueOf(entityType.toUpperCase()))
                        .setParameter(Constants.CERTIFICATE_SERIAL_ID_PARAM, certificateSerialID).setParameter(Constants.CERTIFICATE_STATUS_PARAM, TDPSCertificateStatus.valueOf(certificateStatus)))
                .thenReturn(query);
        Mockito.when(
                query.setParameter(Constants.ENTITY_NAME_PARAM, entityName).setParameter(Constants.ENTITY_TYPE_PARAM, TDPSEntity.valueOf(entityType.toUpperCase()))
                        .setParameter(Constants.CERTIFICATE_SERIAL_ID_PARAM, certificateSerialID).setParameter(Constants.CERTIFICATE_STATUS_PARAM, TDPSCertificateStatus.valueOf(certificateStatus))
                        .setParameter(Constants.ISSUER_NAME_PARAM, issuerName)).thenReturn(query);
        Mockito.when(
                query.setParameter(Constants.ENTITY_NAME_PARAM, entityName).setParameter(Constants.ENTITY_TYPE_PARAM, TDPSEntity.valueOf(entityType.toUpperCase()))
                        .setParameter(Constants.CERTIFICATE_SERIAL_ID_PARAM, certificateSerialID).setParameter(Constants.CERTIFICATE_STATUS_PARAM, TDPSCertificateStatus.valueOf(certificateStatus))
                        .setParameter(Constants.ISSUER_NAME_PARAM, issuerName).getResultList()).thenReturn(tDPSEntityData);
        Mockito.when(tDPSEntityData.get(0)).thenReturn(tdpsEntity);

        persistenceManager.getCertificate(entityName, entityType, issuerName, certificateStatus, certificateSerialID);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetCertificateForDefault() {

        Mockito.when(entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType")).thenReturn(query);
        Mockito.when(entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType").setParameter("entityName", entityName)).thenReturn(query);
        Mockito.when(
                entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType").setParameter("entityName", entityName)
                        .setParameter("entityType", TDPSEntity.valueOf(entityType.toUpperCase()))).thenReturn(query);
        Mockito.when(
                entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType").setParameter("entityName", entityName)
                        .setParameter("entityType", TDPSEntity.valueOf(entityType.toUpperCase())).setParameter("serialNo", serialNo)).thenReturn(query);
        Mockito.when(
                entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType").setParameter("entityName", entityName)
                        .setParameter("entityType", TDPSEntity.valueOf(entityType.toUpperCase())).setParameter("serialNo", serialNo)).thenThrow(new PersistenceException());

        persistenceManager.getCertificate(entityType, entityName, serialNo, certificateStatus, certificateSerialID);

    }

    @Test(expected = CertificateNotFoundException.class)
    public void testgetCertificateCertificateNotFoundException() {

        Mockito.when(entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType")).thenThrow(new NoResultException());

        persistenceManager.getCertificate(entityType, entityName, serialNo, certificateStatus, certificateSerialID);

    }

    @Test(expected = DataLookupException.class)
    public void testgetCertificateNonUniqueResultException() {

        Mockito.when(entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType")).thenThrow(new NonUniqueResultException());

        persistenceManager.getCertificate(entityType, entityName, serialNo, certificateStatus, certificateSerialID);
        Mockito.verify(logger).error("There could be multiple records in DB {} ", String.format(STRING_FORMATTER, entityName, entityType, certificateStatus, certificateSerialID, issuerName));

    }

    @Test(expected = DataLookupException.class)
    public void testgetCertificatePersistenceException() {

        Mockito.when(entityManager.createNamedQuery("TDPSEntityData.findByEntityNameAndEntityType")).thenThrow(new PersistenceException());

        persistenceManager.getCertificate(entityType, entityName, serialNo, certificateStatus, certificateSerialID);
        Mockito.verify(logger).error("Internal DB error while fetching data {}", String.format(STRING_FORMATTER, entityName, entityType, certificateStatus, certificateSerialID, issuerName));

    }

}
