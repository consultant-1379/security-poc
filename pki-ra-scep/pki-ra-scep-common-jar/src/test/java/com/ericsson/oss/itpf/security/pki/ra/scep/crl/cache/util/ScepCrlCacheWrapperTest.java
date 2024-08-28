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
package com.ericsson.oss.itpf.security.pki.ra.scep.crl.cache.util;

import javax.cache.Cache;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pkira.scep.cdt.ScepCrl;

/**
 * Test class for ScepCrlCacheWrapper.
 * 
 * @author xkumkam
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class ScepCrlCacheWrapperTest {

    @InjectMocks
    ScepCrlCacheWrapper scepCrlCacheWrapper;

    @Mock
    Cache<String, ScepCrl> scepCrlCache;

    @Mock
    Logger logger;

    @Mock
    ScepCrl scepCrl;

    private static final String issuerName = "Root_CA";

    /**
     * Method to test updation of crlCache.
     */
    @Test
    public void testInsert() {
        scepCrlCacheWrapper.insertOrUpdate(issuerName, scepCrl);

        Mockito.verify(logger).info("crl is inserted into cache for issuer {} ", issuerName);
    }

    /**
     * Method to test insertion of crlCache.
     */
    @Test
    public void testUpdate() {
        Mockito.when(scepCrlCache.containsKey(issuerName)).thenReturn(true);
        scepCrlCacheWrapper.insertOrUpdate(issuerName, scepCrl);

        Mockito.verify(logger).info("crl is updated in the cache for issuer {} ", issuerName);
    }

    /**
     * Method to test get scepCrl.
     */
    @Test
    public void testGetScepCrl() {
        scepCrlCacheWrapper.get(issuerName);

        Mockito.verify(logger).info("GetCRL from cache for issuer {} ", issuerName);
    }

}
