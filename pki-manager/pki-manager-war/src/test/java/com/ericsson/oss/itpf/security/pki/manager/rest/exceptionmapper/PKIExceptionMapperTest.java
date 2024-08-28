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
package com.ericsson.oss.itpf.security.pki.manager.rest.exceptionmapper;

import static org.junit.Assert.assertEquals;

import javax.ws.rs.core.Response;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.rest.util.CommonUtil;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ExceptionMapper;

/**
 * Test class for {@link CANotFoundExceptionMapper}
 * 
 * @author xhemgan
 * @version 1.1.30
 */
@RunWith(MockitoJUnitRunner.class)
public class PKIExceptionMapperTest extends ExceptionMapper {

    @InjectMocks
    PKIExceptionMapper exceptionMapper;

    @Mock
    CommonUtil commonUtil;

    @Spy
    Logger logger = LoggerFactory.getLogger(PKIExceptionMapper.class);

    /**
     * Method to test toResponse of {@link Exception}
     */
    @Test
    public void testToResponse() {

        Mockito.when(commonUtil.getJSONErrorMessage(INVALID_VALIDITY)).thenReturn(getJSONErrorMessage(INVALID_VALIDITY));

        final Response response = exceptionMapper.toResponse(new IllegalArgumentException(INVALID_VALIDITY));

        assertEquals(STATUS_BAD_REQUEST, response.getStatus());
        assertEquals(getJSONErrorMessage(INVALID_VALIDITY), response.getEntity());
    }
}
