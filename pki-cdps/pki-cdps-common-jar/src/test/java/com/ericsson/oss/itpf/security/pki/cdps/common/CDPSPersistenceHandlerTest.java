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
package com.ericsson.oss.itpf.security.pki.cdps.common;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.PersistenceException;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLDistributionPointServiceException;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.cdps.common.constant.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData;
import com.ericsson.oss.itpf.security.pki.common.util.CRLUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CRLConversionException;
import com.ericsson.oss.itpf.security.pki.common.validator.X509CRLValidator;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLExpiredException;

/**
 * Test Class for CDPSPersistenceHandler.
 * 
 * @author xkumkam
 *
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(CRLUtility.class)
public class CDPSPersistenceHandlerTest {

    @InjectMocks
    CDPSPersistenceHandler cdpsPersistenceHandler;

    @Mock
    private Logger logger;

    @Mock
    private PersistenceManager persistenceManager;

    @Mock
    private X509CRLValidator x509CRLValidator;

    @Mock
    private SystemRecorder systemRecorder;

    private static final String CA_NAME = "caName";
    private static final String CERT_SERIALNUMBER = "certSerialNumber";
    private List<CDPSEntityData> cdpsCrlEntityList = new ArrayList<CDPSEntityData>();

    @Before
    public void SetUpData() {
        cdpsCrlEntityList.add(CDPSEntitySetUpData.getCDPSEntityForEqual());
    }

    @Test(expected = CRLNotFoundException.class)
    public void testGetCRL_CRLNotFoundException() {
        cdpsPersistenceHandler.getCRL(CA_NAME, CERT_SERIALNUMBER);

        Mockito.verify(logger).error(ErrorMessages.ERR_CRL_NOT_FOUND);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetCRL() {
        Mockito.when(persistenceManager.findEntitiesWhere(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(cdpsCrlEntityList);
        byte[] crlByteArray = cdpsPersistenceHandler.getCRL(CA_NAME, CERT_SERIALNUMBER);

        Assert.assertNotNull(crlByteArray);
    }

    @SuppressWarnings("unchecked")
    @Test(expected = CRLDistributionPointServiceException.class)
    public void testGetCRL_CRLDistributionPointServiceException() {
        Mockito.when(persistenceManager.findEntitiesWhere(Mockito.any(Class.class), Mockito.anyMap())).thenThrow(new PersistenceException());
        cdpsPersistenceHandler.getCRL(CA_NAME, CERT_SERIALNUMBER);

        Mockito.verify(logger).error(ErrorMessages.ERR_INTERNAL_ERROR);
    }

    @SuppressWarnings({ "unchecked" })
    @Test(expected = CRLConversionException.class)
    public void testGetCRL_CRLConversionException() {
        Mockito.when(persistenceManager.findEntitiesWhere(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(cdpsCrlEntityList);
        PowerMockito.mockStatic(CRLUtility.class);
        PowerMockito.doThrow(new CRLConversionException()).when(CRLUtility.class);
        CRLUtility.getX509CRL(cdpsCrlEntityList.get(0).getCrl());
        cdpsPersistenceHandler.getCRL(CA_NAME, CERT_SERIALNUMBER);
    }

    @SuppressWarnings("unchecked")
    @Test(expected = CRLExpiredException.class)
    public void testGetCRL_CRLExpiredException() {
        Mockito.when(persistenceManager.findEntitiesWhere(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(cdpsCrlEntityList);
        Mockito.doThrow(new CRLExpiredException()).when(x509CRLValidator).checkCRLvalidity(CRLUtility.getX509CRL(cdpsCrlEntityList.get(0).getCrl()));
        cdpsPersistenceHandler.getCRL(CA_NAME, CERT_SERIALNUMBER);
    }

}
