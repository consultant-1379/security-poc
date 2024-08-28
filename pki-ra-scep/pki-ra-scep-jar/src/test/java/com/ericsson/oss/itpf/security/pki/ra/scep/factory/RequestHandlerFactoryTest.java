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
package com.ericsson.oss.itpf.security.pki.ra.scep.factory;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepRequest;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.Operation;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.NotImplementedOperException;

/**
 * This class contains the tests for RequestHandlerFactory
 */
@RunWith(MockitoJUnitRunner.class)
public class RequestHandlerFactoryTest {
    @InjectMocks
    private RequestHandlerFactory requestHandleFactory;

    @Mock
    private Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    private PkiScepRequest pkiScepRequest;

    /**
     * setUp method initializes the required data which are used as a part of the test cases.
     */
    @Before
    public void setup() {
        pkiScepRequest = new PkiScepRequest();
    }

    /**
     * This method tests Implementation handler for GETNEXTCACERT as null
     */
    @Test(expected = NotImplementedOperException.class)
    public void testGetNextCACert() {
        pkiScepRequest.setOperation(Operation.GETNEXTCACERT);
        requestHandleFactory.getInstance(pkiScepRequest);
    }

    /**
     * This method tests Implementation handler for GETCACAPS as null
     */

    @Test(expected = NotImplementedOperException.class)
    public void testGetCACaps() {
        pkiScepRequest.setOperation(Operation.GETCACAPS);
        requestHandleFactory.getInstance(pkiScepRequest);
    }

    /**
     * This method tests Implementation handler for PKIOPERATION
     */
    @Test
    public void testPKIOperation() {
        pkiScepRequest.setOperation(Operation.PKIOPERATION);
        requestHandleFactory.getInstance(pkiScepRequest);
        Mockito.verify(logger).debug("End of getInstance method of RequestHandlerFactory");
    }

    /**
     * This method tests Implementation handler for GETCACERT
     */
    @Test
    public void testGetCACert() {
        pkiScepRequest.setOperation(Operation.GETCACERT);
        requestHandleFactory.getInstance(pkiScepRequest);
        Mockito.verify(logger).debug("End of getInstance method of RequestHandlerFactory");
    }

    /**
     * This method tests Implementation handler for GETCACERTCHAIN
     */
    @Test
    public void testGetCACertChain() {
        pkiScepRequest.setOperation(Operation.GETCACERTCHAIN);
        requestHandleFactory.getInstance(pkiScepRequest);
        Mockito.verify(logger).debug("End of getInstance method of RequestHandlerFactory");
    }
}
