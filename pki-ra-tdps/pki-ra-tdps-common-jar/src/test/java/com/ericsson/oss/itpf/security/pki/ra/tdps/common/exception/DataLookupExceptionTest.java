/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.DataLookupException;

@RunWith(MockitoJUnitRunner.class)
public class DataLookupExceptionTest {

    @InjectMocks
    DataLookupException dataLookupException;

    @Test(expected = DataLookupException.class)
    public void testDataLookupExceptionwithCause() {

        throw new DataLookupException(new Exception());
    }

    @Test(expected = DataLookupException.class)
    public void testDataLookupException() {

        throw new DataLookupException();
    }

    @Test(expected = DataLookupException.class)
    public void testDataLookupExceptionwithMessage() {

        throw new DataLookupException("Exception");
    }

    @Test(expected = DataLookupException.class)
    public void testDataLookupExceptionewithBoth() {

        throw new DataLookupException("Exception", new Exception());
    }

}
