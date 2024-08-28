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

package com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.impl;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

/**
 * Test Class for CrlCacheLocalServiceBean.
 *
 * @author xkumkam
 */
@RunWith(MockitoJUnitRunner.class)
public class CrlCacheLocalServiceBeanTest {

    @InjectMocks
    CrlCacheLocalServiceBean crlCacheLocalServiceBean;

    @Mock
    CRLCacheUtil crlCacheUtil;

    @Mock
    Logger logger;

    private final String crlFileName = "ENM_OA_CA";

    /**
     * Method to test updateCrlCache with valid crlFileName.
     *
     * @throws CertificateException
     * @throws CRLException
     * @throws NoSuchProviderException
     * @throws IOException
     */
    @Test
    public void testupdateCrlCache() throws CertificateException, CRLException, NoSuchProviderException, IOException {
        crlCacheLocalServiceBean.updateCrlCache(crlFileName);

        Mockito.verify(logger).info("Successfully updated CRL cache for the file {}" , crlFileName);
    }

}
