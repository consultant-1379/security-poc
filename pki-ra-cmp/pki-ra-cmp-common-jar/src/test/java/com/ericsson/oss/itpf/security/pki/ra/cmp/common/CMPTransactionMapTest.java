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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.ra.cmp.asynchresponse.RestSynchResponse;

@RunWith(MockitoJUnitRunner.class)
public class CMPTransactionMapTest {

    @InjectMocks
    CMPTransactionResponseMap cmpTransactionResponseMap;

    @Mock
    RestSynchResponse response;

    @Test
    public void testGetAsyncResponse() {
        cmpTransactionResponseMap.getRestSynchResponse("transactionID");
    }

    @Test
    public void testaddAsyncResponse() {
        cmpTransactionResponseMap.putRestSynchResponse("transactionID", response);
    }

}
