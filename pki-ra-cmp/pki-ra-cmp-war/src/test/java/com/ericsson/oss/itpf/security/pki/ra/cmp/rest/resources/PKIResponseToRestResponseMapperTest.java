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
package com.ericsson.oss.itpf.security.pki.ra.cmp.rest.resources;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class PKIResponseToRestResponseMapperTest {

    @InjectMocks
    PKIResponseToRestResponseMapper pKIResponseToRestResponseMapper;

    @Test
    public void testToRestResponse() {
        byte[] pKISignedResponse = new byte[1];
        pKIResponseToRestResponseMapper.toRestResponse(pKISignedResponse);
    }

}
