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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator;

import static org.junit.Assert.*;

import java.security.cert.CRLException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLVersion;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test.CRLSetUpData;

/**
 * Test Class for CrlGeneratorFactory.
 */
@RunWith(MockitoJUnitRunner.class)
public class CrlGeneratorFactoryTest {
    @InjectMocks
    CrlGeneratorFactory crlGeneratorFactory;

    @Mock
    CrlGenerator crlV2Generator;

    private static CertificateAuthority certificateAuthority;

    /**
     * Prepares initial Data.
     */
    @Before
    public void SetUpData() {
        certificateAuthority = CRLSetUpData.getCertificateAuthority();
    }

    /**
     * Method to test getCrlGenerator.
     * 
     * @throws CRLException
     */
    @Test
    public void getGetCrlGenerator() {
        CrlGenerator crlGenerator = crlGeneratorFactory.getCrlGenerator(certificateAuthority);
        assertNotNull(crlGenerator);
        assertEquals(CRLVersion.V2, certificateAuthority.getCrlGenerationInfo().get(0).getVersion());
        assertEquals(crlV2Generator, crlGenerator);
    }

}
