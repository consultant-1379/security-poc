/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.upgrade;

import static org.mockito.Mockito.times;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RunWith(MockitoJUnitRunner.class)
public class SyncMismatchEntitiesPersistenceHandlerTest {

    @InjectMocks
    SyncMismatchEntitiesPersistenceHandler syncMismatchEntitiesPersistenceHandler;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    EntityPersistenceHandler<Entity> entityPersistenceHandler;

    private EntityData entityData;
    private EntityInfoData entityInfoData;
    private SubjectIdentificationData subjectIdentificationData;

    private static final String subjectDN = "CN=ENMSubCA";

    @Before
    public void SetUp() {
        entityData = new EntityData();
        entityInfoData = new EntityInfoData();
        subjectIdentificationData = new SubjectIdentificationData();

        entityInfoData.setSubjectDN(subjectDN);
        entityData.setEntityInfoData(entityInfoData);
    }

    @Test
    public void testSyncMismatchEntities() {
        final List<BigInteger> entityIds = new ArrayList<BigInteger>();
        final BigInteger e = new BigInteger("2");
        entityIds.add(e);

        final String qlString = "select id from entity where id not in (select entity_id from subject_identification_details)";
        final String qlString2 = "select id from subject_identification_details where entity_id not in (select id from entity)";
        final String qlString3 = "select entity_id from subject_identification_details sd, entity ee where encode(sd.subject_dn_hash, 'hex') != encode(digest(lower(ee.subject_dn), 'sha256'), 'hex') and  sd.entity_id=ee.id;";

        Mockito.when(persistenceManager.findIdsByNativeQuery(qlString)).thenReturn(entityIds);
        Mockito.when(entityPersistenceHandler.getEntityById(e.longValue(), EntityData.class)).thenReturn(entityData);

        Mockito.when(persistenceManager.findIdsByNativeQuery(qlString2)).thenReturn(entityIds);
        Mockito.when(entityPersistenceHandler.getEntityById(e.longValue(), SubjectIdentificationData.class)).thenReturn(subjectIdentificationData);

        Mockito.when(persistenceManager.findIdsByNativeQuery(qlString3)).thenReturn(entityIds);

        syncMismatchEntitiesPersistenceHandler.syncMismatchEntities();

        Mockito.verify(persistenceManager, times(2)).updateEntity(entityData);
        Mockito.verify(persistenceManager).deleteEntity(subjectIdentificationData);
    }
}
