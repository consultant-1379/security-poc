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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.mappers;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.mappers.TDPSEntityTypeMapper;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType;

@RunWith(MockitoJUnitRunner.class)
public class TDPSEntityTypeMapperTest {

    @InjectMocks
    TDPSEntityTypeMapper tdpsEntityTypeMapper;

    @Mock
    Logger logger;

    @Test
    public void testToModelEntity() {
        final EntityType entityType = EntityType.ENTITY;
        TDPSEntityType tdpsEntityType = tdpsEntityTypeMapper.toModel(entityType);

        Assert.assertEquals(TDPSEntityType.ENTITY, tdpsEntityType);

    }

    @Test
    public void testToModelCAEntity() {
        final EntityType entityType = EntityType.CA_ENTITY;
        TDPSEntityType tdpsEntityType = tdpsEntityTypeMapper.toModel(entityType);

        Assert.assertEquals(TDPSEntityType.CA_ENTITY, tdpsEntityType);

    }

    @Test
    public void testFromModelEntity() {

        final TDPSEntityType tdpsEntityType = TDPSEntityType.ENTITY;
        tdpsEntityTypeMapper.fromModel(tdpsEntityType);
        Assert.assertEquals(TDPSEntityType.ENTITY, tdpsEntityType);
    }

    @Test
    public void testFromModelCAEntity() {

        final TDPSEntityType tdpsEntityType = TDPSEntityType.CA_ENTITY;
        tdpsEntityTypeMapper.fromModel(tdpsEntityType);
        Assert.assertEquals(TDPSEntityType.CA_ENTITY, tdpsEntityType);
    }

    @Test
    public void testFromModel() {

        final TDPSEntityType tdpsEntityType = TDPSEntityType.UNKNOWN_ENTITY;
        tdpsEntityTypeMapper.fromModel(tdpsEntityType);
        Assert.assertEquals(TDPSEntityType.UNKNOWN_ENTITY, tdpsEntityType);
    }

}
