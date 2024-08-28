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
package com.ericsson.oss.itpf.security.pki.cdps.ejb;

import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLDistributionPointServiceException;
import com.ericsson.oss.itpf.security.pki.cdps.common.constant.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.cdps.ejb.CRLDistributionPointServiceBean;
import com.ericsson.oss.itpf.security.pki.cdps.impl.CRLDistributionPointServiceManager;

/**
 * This class used to test CRLDistributionPointServiceBean functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CRLDistributionPointServiceBeanTest {

    @InjectMocks
    private CRLDistributionPointServiceBean crlDistributionPointServiceBean;

    @Mock
    private Logger logger;

    @Mock
    private CRLDistributionPointServiceManager crlDistributionPointServiceManager;

    private String caName;
    private String certSerialNumber;
    private byte[] crlData;
    private byte[] crlRetutn;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        caName = "CRL_CA";
        certSerialNumber = "2014TYURT6Y7UIKJ89UI8976TYFG673D";
        crlData = getX509CRL("src/test/resources/crls/testCA.crl");
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.ejb.CRLDistributionPointServiceBean#getCRL(java.lang.String, java.lang.String)}.
     */
    @Test
    public void testGetCRL() {

        Mockito.when(crlDistributionPointServiceManager.getCRL(caName, certSerialNumber)).thenReturn(crlData);

        crlRetutn = crlDistributionPointServiceBean.getCRL(caName, certSerialNumber);

        assertNotNull(crlRetutn);
        assertEquals(crlData, crlRetutn);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.ejb.CRLDistributionPointServiceBean#getCRL(java.lang.String, java.lang.String)}.
     */
    @Test(expected = CRLDistributionPointServiceException.class)
    public void testGetCRLThrowsCRLDistributionPointServiceException() {

        Mockito.when(crlDistributionPointServiceManager.getCRL(caName, certSerialNumber)).thenThrow(new CRLDistributionPointServiceException(ErrorMessages.ERR_INTERNAL_ERROR));

        crlDistributionPointServiceBean.getCRL(caName, certSerialNumber);

    }

    private byte[] getX509CRL(String fileName) throws FileNotFoundException, CRLException, java.security.cert.CertificateException {

        FileInputStream inputStream = new FileInputStream(fileName);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509CRL x509crl = (X509CRL) certificateFactory.generateCRL(inputStream);

        return x509crl.getEncoded();
    }

}
