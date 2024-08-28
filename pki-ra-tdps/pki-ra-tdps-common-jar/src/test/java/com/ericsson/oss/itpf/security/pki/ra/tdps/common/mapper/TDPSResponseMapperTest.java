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

import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSResponse;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper.TDPSResponseMapper;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSResponseType;

@RunWith(MockitoJUnitRunner.class)
public class TDPSResponseMapperTest {

    @InjectMocks
    TDPSResponseMapper tdpsResponseMapper;

    @Test
    public void testFromModel() {

        TDPSResponseType tdpsResponseType = TDPSResponseType.SUCCESS;
        TDPSResponse tdpsResponse = tdpsResponseMapper.fromModel(tdpsResponseType);

        Assert.assertEquals(tdpsResponseType + "", tdpsResponse + "");
    }

    @Test
    public void testFromModelFailure() {

        TDPSResponseType tdpsResponseType = TDPSResponseType.FAILURE;
        TDPSResponse tdpsResponse = tdpsResponseMapper.fromModel(tdpsResponseType);

        Assert.assertEquals(tdpsResponseType + "", tdpsResponse + "");

    }

    @Test
    public void testFromModelUnknownStatus() {

        TDPSResponseType tdpsResponseType = TDPSResponseType.UNKNOWN_STATUS;
        TDPSResponse tdpsResponse = tdpsResponseMapper.fromModel(tdpsResponseType);

        Assert.assertEquals(tdpsResponseType + "", tdpsResponse + "");

    }

    @Test
    public void testToModel() {

        TDPSResponse tdpsResponse = TDPSResponse.FAILURE;
        TDPSResponseType tdpsResponsetype = tdpsResponseMapper.toModel(tdpsResponse);

        Assert.assertEquals(tdpsResponse + "", tdpsResponsetype + "");
    }

    @Test
    public void testToModelSuccess() {

        TDPSResponse tdpsResponse = TDPSResponse.SUCCESS;
        TDPSResponseType tdpsResponsetype = tdpsResponseMapper.toModel(tdpsResponse);

        Assert.assertEquals(tdpsResponse + "", tdpsResponsetype + "");
    }

    @Test
    public void testToModelUnknownStatus() {

        TDPSResponse tdpsResponse = TDPSResponse.UNKNOWN_STATUS;
        TDPSResponseType tdpsResponsetype = tdpsResponseMapper.toModel(tdpsResponse);

        Assert.assertEquals(tdpsResponse + "", tdpsResponsetype + "");
    }

}
