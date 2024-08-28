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
package com.ericsson.oss.itpf.security.pki.ra.scep.ejb;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepRequest;
import com.ericsson.oss.itpf.security.pki.ra.scep.factory.RequestHandlerFactory;
import com.ericsson.oss.itpf.security.pki.ra.scep.handler.RequestHandler;

/**
 * This class will test PkiScepServiceBean class
 */
@RunWith(MockitoJUnitRunner.class)
public class PkiScepServiceBeanTest {

    @InjectMocks
    PkiScepServiceBean pkiScepServiceBean;

    @Mock
    private RequestHandlerFactory reqHandlerFactory;

    @Mock
    private PkiScepRequest pkiScepRequest;

    @Mock
    RequestHandler requestHandler;

    @Mock
    Logger logger;

    /**
     * This method test handleRequest method of PkiScepServiceBean class
     */
    @Test
    public void testHandleRequest() {

        Mockito.when(reqHandlerFactory.getInstance(pkiScepRequest)).thenReturn(requestHandler);
        pkiScepServiceBean.handleRequest(pkiScepRequest);

        Mockito.verify(reqHandlerFactory).getInstance(pkiScepRequest);

    }
}
