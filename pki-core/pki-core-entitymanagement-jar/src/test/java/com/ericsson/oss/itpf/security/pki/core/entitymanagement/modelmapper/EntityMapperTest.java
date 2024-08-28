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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.modelmapper;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.EntityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.common.utils.EntitiesSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class EntityMapperTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityModelMapper.class);

    @InjectMocks
    EntityModelMapper entityMapper;

    @Mock
    PersistenceManager persistenceManager;

    EntityInfo entityInfo;
    EntityInfoData entityInfoData;

    @Before
    public void setup() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

        entityInfo = entitiesSetUpData.getEntityInfo();
        entityInfoData = entitiesSetUpData.getEntityInfoData();
        entityInfo = entitiesSetUpData.getEntityInfo();
        entityInfoData = entitiesSetUpData.getEntityInfoData();
    }

    @Test
    public void toAPIFromModel() throws Exception {

        final EntityInfo entityInfo = entityMapper.toAPIFromModel(entityInfoData);

        assertEquals(entityInfoData.getId(), entityInfo.getId());
        assertEquals(entityInfoData.getName(), entityInfo.getName());
        assertEquals(entityInfoData.getSubjectDN(), entityInfo.getSubject().toASN1String());
        assertEquals(entityInfoData.getSubjectAltName(), JsonUtil.getJsonFromObject(entityInfo.getSubjectAltName()));
    }

    @Test
    public void testfromAPIToModel() {

        final EntityInfoData entityInfoData = entityMapper.fromAPIToModel(entityInfo, OperationType.CREATE);

        assertEquals(entityInfo.getId(), entityInfoData.getId());
        assertEquals(entityInfo.getName(), entityInfoData.getName());
        assertEquals(entityInfo.getSubject().toASN1String(), entityInfoData.getSubjectDN());
        assertEquals(JsonUtil.getJsonFromObject(entityInfo.getSubjectAltName()), entityInfoData.getSubjectAltName());
    }

}
