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
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.CertificateNotPublishedException;

@RunWith(MockitoJUnitRunner.class)
public class CertificateNotPublishedExceptionTest {

    @InjectMocks
    CertificateNotPublishedException certificateNotPublishedException;

    @Test(expected = CertificateNotPublishedException.class)
    public void testCertificateNotPublishedExceptionwithCause() {

        throw new CertificateNotPublishedException(new Exception());
    }

    @Test(expected = CertificateNotPublishedException.class)
    public void testCertificateNotPublishedException() {

        throw new CertificateNotPublishedException();
    }

    @Test(expected = CertificateNotPublishedException.class)
    public void testCertificateNotPublishedExceptionwithMessage() {

        throw new CertificateNotPublishedException("Exception");
    }

    @Test(expected = CertificateNotPublishedException.class)
    public void testCertificateNotPublishedExceptionwithBoth() {

        throw new CertificateNotPublishedException("Exception", new Exception());
    }

}
