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
package com.ericsson.oss.itpf.security.pki.cdps.impl;

import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.*;
import com.ericsson.oss.itpf.security.pki.cdps.common.CDPSPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.cdps.common.constant.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.cdps.impl.CRLDistributionPointServiceManager;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CRLConversionException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLExpiredException;

/**
 * This class used to test CRLResponseMessageListener functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CRLDistributionPointServiceManagerTest {

    @InjectMocks
    CRLDistributionPointServiceManager crlDistributionPointServiceManager;

    @Mock
    private CDPSPersistenceHandler cdpsPersistenceHandler;

    @Mock
    private SystemRecorder systemRecorder;

    private String caName;
    private String certSerialNumber;
    private byte[] crlContent;
    private byte[] return_Value;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        caName = "CRL_CA";
        certSerialNumber = "20142345RYH7653WKSIJRFRFDGFRDR3D";
        crlContent = getX509CRL("src/test/resources/crls/testCA.crl");
        return_Value = new byte[0];

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.persistence.handler.CRLDistributionPointServiceManager#getCRL(java.lang.String, java.lang.String)}.
     */
    @Test
    public void testGetCRL() {

        Mockito.when(cdpsPersistenceHandler.getCRL(caName, certSerialNumber)).thenReturn(crlContent);

        return_Value = crlDistributionPointServiceManager.getCRL(caName, certSerialNumber);

        assertNotNull(return_Value);
        assertArrayEquals(crlContent, return_Value);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.persistence.handler.CRLDistributionPointServiceManager#getCRL(java.lang.String, java.lang.String)}.
     */
    @Test(expected = InvalidCRLException.class)
    public void testGetCRLThrowsCRLConversionException() {

        Mockito.when(cdpsPersistenceHandler.getCRL(caName, certSerialNumber)).thenThrow(new CRLConversionException());

        crlDistributionPointServiceManager.getCRL(caName, certSerialNumber);

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.persistence.handler.CRLDistributionPointServiceManager#getCRL(java.lang.String, java.lang.String)}.
     */
    @Test(expected = CRLDistributionPointServiceException.class)
    public void testGetCRLThrowsCRLDistributionPointServiceException() {

        Mockito.when(cdpsPersistenceHandler.getCRL(caName, certSerialNumber)).thenThrow(new CRLDistributionPointServiceException(ErrorMessages.ERR_INTERNAL_ERROR));

        crlDistributionPointServiceManager.getCRL(caName, certSerialNumber);

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.persistence.handler.CRLDistributionPointServiceManager#getCRL(java.lang.String, java.lang.String)}.
     */
    @Test(expected = InvalidCRLException.class)
    public void testGetCRLThrowsCRLExpiredException() {

        Mockito.when(cdpsPersistenceHandler.getCRL(caName, certSerialNumber)).thenThrow(new CRLExpiredException());

        crlDistributionPointServiceManager.getCRL(caName, certSerialNumber);

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.persistence.handler.CRLDistributionPointServiceManager#getCRL(java.lang.String, java.lang.String)}.
     */
    @Test(expected = CRLNotFoundException.class)
    public void testGetCRLThrowsCRLNotFoundException() {

        Mockito.when(cdpsPersistenceHandler.getCRL(caName, certSerialNumber)).thenThrow(new CRLNotFoundException(ErrorMessages.ERR_CRL_NOT_FOUND));

        crlDistributionPointServiceManager.getCRL(caName, certSerialNumber);

    }

    private byte[] getX509CRL(String fileName) throws FileNotFoundException, CRLException, java.security.cert.CertificateException {

        FileInputStream inputStream = new FileInputStream(fileName);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509CRL x509crl = (X509CRL) certificateFactory.generateCRL(inputStream);

        return x509crl.getEncoded();
    }
}
