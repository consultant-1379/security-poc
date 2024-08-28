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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.impl.service;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.impl.RevocationManager;

@RunWith(MockitoJUnitRunner.class)
public class RevocationServiceBeanTest {

    @InjectMocks
    RevocationServiceBean revocationServiceBean;

    @Mock
    Logger logger;

    @Mock
    RevocationManager certificateRevocationManager;

    private RevocationRequest revocationRequest = new RevocationRequest();

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.core.crlmanagement.impl.service.RevocationServiceBean#revokeCertificate(com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequest)}
     * .
     */
    @Test
    public void testRevokeCertificate() {

        revocationServiceBean.revokeCertificate(revocationRequest);

        Mockito.verify(certificateRevocationManager).revokeCertificateByRevocationRequest(revocationRequest);

    }

}
