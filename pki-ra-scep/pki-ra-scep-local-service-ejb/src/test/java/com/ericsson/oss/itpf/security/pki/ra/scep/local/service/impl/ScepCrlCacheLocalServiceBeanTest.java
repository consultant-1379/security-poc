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
package com.ericsson.oss.itpf.security.pki.ra.scep.local.service.impl;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateUtilityException;
import com.ericsson.oss.itpf.security.pki.ra.scep.crl.cache.util.ScepCrlCacheUtil;

/**
 * This class will test ScepCrlCacheLocalServiceBean class
 */
@RunWith(MockitoJUnitRunner.class)
public class ScepCrlCacheLocalServiceBeanTest {

    @InjectMocks
    ScepCrlCacheLocalServiceBean scepCrlCacheLocalServiceBean;

    @Mock
    private ScepCrlCacheUtil scepCrlCacheUtil;

    @Mock
    Logger logger;

    @Test
    public void updateCrlCache() throws CertificateException, CRLException, IOException, NoSuchProviderException, CertificateUtilityException {
        String crlFileName = null;
        scepCrlCacheLocalServiceBean.updateCrlCache(crlFileName);
        Mockito.verify(scepCrlCacheUtil).updateCache(crlFileName);
    }

}
