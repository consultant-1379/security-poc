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
package com.ericsson.oss.itpf.security.pki.manager.rest.serializers;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data.EntitiesSetUpData;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Test class for {@link EntityInfoSerializer}
 * 
 * @author tcspred
 * @version 1.1.30
 */

@RunWith(MockitoJUnitRunner.class)
public class EntityInfoSerializerTest {

    @Mock
    EntityInfoSerializer entityInfoSerializer;

    final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
    JsonGenerator generator;
    SerializerProvider provider;

    Entity entity;
    EntityData entityData;
    List<EntityData> entityDataList;
    List<Entity> entityList;

    long id;
    String name;

    EntityInfo entityInfo;

    ObjectMapper mapper;

    @Before
    public void setUp() {

        entityDataList = entitiesSetUpData.getEntityDataList();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entityData = entityDataList.get(0);
        id = entity.getEntityInfo().getId();
        name = entity.getEntityInfo().getName();
        entityInfo = entity.getEntityInfo();
        entityInfo.setStatus(EntityStatus.NEW);

        mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(EntityInfo.class, new EntityInfoSerializer());
        mapper.registerModule(module);
    }

    /**
     * Method for Serialize()
     * 
     * @throws JsonProcessingException
     *             , IOException
     */
    @Test
    public void testSerialize() throws JsonProcessingException, IOException {

        final String expectedJsonEntityCategory = "{\"id\":1,\"name\":\"ENMService\",\"oTPCount\":5,\"oTP\":null,\"active\":false,\"subject\":{\"subjectFields\":[{\"type\":\"COMMON_NAME\",\"value\":\"ENM_Root\"}]},\"subjectAltName\":{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"www.xyz.com\"}}]}}";

        entityInfoSerializer.serialize(entityInfo, generator, provider);

        final String jsonOutput = mapper.writeValueAsString(entityInfo);
        
        assertEquals(expectedJsonEntityCategory, jsonOutput);

    }

}
