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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

@RunWith(MockitoJUnitRunner.class)
public class CertificateChainBuilderTest {

    @InjectMocks
    CertificateChainBuilder certificateChainBuilder;

    List<Certificate> certificates = null;

    @Before
    public void setUp() {
        certificates = new ArrayList<Certificate>();
    }

    /**
     * Test case for generating CertificateChain object
     */
    @Test
    public void testBuild() {

        certificateChainBuilder.certificates(certificates);
        final CertificateChain certificateChain = certificateChainBuilder.build();

        assertNotNull(certificateChain);
        assertEquals(certificates.size(), certificateChain.getCertificates().size());

    }

    /**
     * Test case for setting certificates to CertificateChain object.
     * 
     */
    @Test
    public void testCertificates() {

        certificateChainBuilder.certificates(certificates);
    }
}
