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
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSEntity;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper.TDPSEntityTypeMapper;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType;

@RunWith(MockitoJUnitRunner.class)
public class TDPSEntityTypeMapperTest {

    @InjectMocks
    TDPSEntityTypeMapper tdpsEntityTypeMapper;

    @Test
    public void testFromModel() {

        TDPSEntityType tdpsEntityType = TDPSEntityType.CA_ENTITY;
        TDPSEntity entityType = tdpsEntityTypeMapper.fromModel(tdpsEntityType);
        Assert.assertEquals(TDPSEntityType.CA_ENTITY + "", entityType + "");
    }

    @Test
    public void testFromModelENTITY() {

        TDPSEntityType tdpsEntityType = TDPSEntityType.ENTITY;
        TDPSEntity entityType = tdpsEntityTypeMapper.fromModel(tdpsEntityType);
        Assert.assertEquals(TDPSEntityType.ENTITY + "", entityType + "");

    }

    @Test
    public void testFromModelUnknownEntity() {

        TDPSEntityType tdpsEntityType = TDPSEntityType.UNKNOWN_ENTITY;
        tdpsEntityTypeMapper.fromModel(tdpsEntityType);

    }

    @Test
    public void testToModel() {

        TDPSEntity entityType = TDPSEntity.CA_ENTITY;
        TDPSEntityType tdpsEntityType = tdpsEntityTypeMapper.toModel(entityType);

        Assert.assertEquals(entityType + "", tdpsEntityType + "");
    }

    @Test
    public void testToModelEntity() {

        TDPSEntity entityType = TDPSEntity.ENTITY;
        TDPSEntityType tdpsEntityType = tdpsEntityTypeMapper.toModel(entityType);

        Assert.assertEquals(entityType + "", tdpsEntityType + "");

    }

    @Test
    public void testToModelUnknown() {

        TDPSEntity entityType = TDPSEntity.UNKNOWN;
        tdpsEntityTypeMapper.toModel(entityType);

    }

}
