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
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.CertificateNotFoundException;

@RunWith(MockitoJUnitRunner.class)
public class CertificateNotFoundExceptionTest {

    @InjectMocks
    CertificateNotFoundException certificateNotFoundException;

    @Test(expected = CertificateNotFoundException.class)
    public void defaultHandle3() {

        throw new CertificateNotFoundException(new Exception());
    }

    @Test(expected = CertificateNotFoundException.class)
    public void defaultHandle() {

        throw new CertificateNotFoundException();
    }

    @Test(expected = CertificateNotFoundException.class)
    public void defaultHandle1() {

        throw new CertificateNotFoundException("Exception");
    }

    @Test(expected = CertificateNotFoundException.class)
    public void defaultHandle2() {

        throw new CertificateNotFoundException("Exception", new Exception());
    }

}
