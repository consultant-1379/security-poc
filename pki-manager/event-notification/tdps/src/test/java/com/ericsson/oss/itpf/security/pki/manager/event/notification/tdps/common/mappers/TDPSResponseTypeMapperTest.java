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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.mappers;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.mappers.TDPSResponseTypeMapper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.model.TDPSAcknowledgementStatus;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSResponseType;

@RunWith(MockitoJUnitRunner.class)
public class TDPSResponseTypeMapperTest {

    @InjectMocks
    TDPSResponseTypeMapper tdpsResponseTypeMapper;

    @Mock
    Logger logger;

    @Test
    public void testFromModelFailure() {

        final TDPSResponseType tdpsResponseType = TDPSResponseType.FAILURE;
        final TDPSAcknowledgementStatus tdpsAcknowledgementStatus = tdpsResponseTypeMapper.fromModel(tdpsResponseType);
        Assert.assertEquals(TDPSAcknowledgementStatus.FAILURE, tdpsAcknowledgementStatus);
    }

    @Test
    public void testFromModelSuccess() {

        final TDPSResponseType tdpsResponseType = TDPSResponseType.SUCCESS;
        final TDPSAcknowledgementStatus tdpsAcknowledgementStatus = tdpsResponseTypeMapper.fromModel(tdpsResponseType);

        Assert.assertEquals(TDPSAcknowledgementStatus.SUCCESS, tdpsAcknowledgementStatus);
    }

    @Test
    public void testFromModel() {

        final TDPSResponseType tdpsResponseType = TDPSResponseType.UNKNOWN_STATUS;
        final TDPSAcknowledgementStatus tdpsAcknowledgementStatus = tdpsResponseTypeMapper.fromModel(tdpsResponseType);

        Assert.assertNull(tdpsAcknowledgementStatus);
    }
}
