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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.builders;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.builders.TDPServiceErrorResponseEventBuilder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSResponseType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPServiceResponse;

@RunWith(MockitoJUnitRunner.class)
public class TDPServiceErrorResponseEventBuilderTest {

    @InjectMocks
    TDPServiceErrorResponseEventBuilder tdpServiceErrorResponseEventBuilder;

    @Test
    public void testBuildErroredResponse() {

        tdpServiceErrorResponseEventBuilder.cause("cause");
        TDPServiceResponse tdpserviceResponse = tdpServiceErrorResponseEventBuilder.buildErroredResponse();

        Assert.assertEquals(TDPSResponseType.FAILURE, tdpserviceResponse.getResponseType());

    }

}
