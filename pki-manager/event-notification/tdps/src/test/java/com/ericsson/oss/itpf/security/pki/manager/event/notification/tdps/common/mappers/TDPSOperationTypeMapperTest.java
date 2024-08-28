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
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.common.enums.TDPSPublishStatusType;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.mappers.TDPSOperationTypeMapper;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSOperationType;

@RunWith(MockitoJUnitRunner.class)
public class TDPSOperationTypeMapperTest {

    @InjectMocks
    TDPSOperationTypeMapper tdpsOperationTypeMapper;

    @Test
    public void testToModelPulish() {

        final TDPSPublishStatusType tdpsPublishStatusType = TDPSPublishStatusType.PUBLISH;
        final TDPSOperationType tdpsOperationType = tdpsOperationTypeMapper.toModel(tdpsPublishStatusType);
        Assert.assertEquals(TDPSOperationType.PUBLISH, tdpsOperationType);

    }

    @Test
    public void testToModelUnpublish() {

        final TDPSPublishStatusType tdpsPublishStatusType = TDPSPublishStatusType.UNPUBLISH;
        final TDPSOperationType tdpsOperationType = tdpsOperationTypeMapper.toModel(tdpsPublishStatusType);
        Assert.assertEquals(TDPSOperationType.UNPUBLISH, tdpsOperationType);
    }

    @Test
    public void testToModel() {
        final TDPSPublishStatusType tdpsPublishStatusType = TDPSPublishStatusType.UNKNOWN;
        final TDPSOperationType tdpsOperationType = tdpsOperationTypeMapper.toModel(tdpsPublishStatusType);
        Assert.assertEquals(TDPSOperationType.UNKNOWN, tdpsOperationType);
    }

    @Test
    public void testFromModelPublish() {
        final TDPSOperationType tdpsOperationType = TDPSOperationType.PUBLISH;

        final TDPSPublishStatusType tdpsPublishStatusType = tdpsOperationTypeMapper.fromModel(tdpsOperationType);
        Assert.assertEquals(TDPSPublishStatusType.PUBLISH, tdpsPublishStatusType);

    }

    @Test
    public void testFromModelUnpublish() {
        final TDPSOperationType tdpsOperationType = TDPSOperationType.UNPUBLISH;

        final TDPSPublishStatusType tdpsPublishStatusType = tdpsOperationTypeMapper.fromModel(tdpsOperationType);
        Assert.assertEquals(TDPSPublishStatusType.UNPUBLISH, tdpsPublishStatusType);

    }

    @Test
    public void testFromModel() {
        final TDPSOperationType tdpsOperationType = TDPSOperationType.UNKNOWN;

        final TDPSPublishStatusType tdpsPublishStatusType = tdpsOperationTypeMapper.fromModel(tdpsOperationType);
        Assert.assertEquals(TDPSPublishStatusType.UNKNOWN, tdpsPublishStatusType);

    }

}
