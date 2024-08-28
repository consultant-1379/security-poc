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
package com.ericsson.oss.itpf.security.pki.cdps.notification.events;

import static org.mockito.Mockito.times;

import java.util.List;

import javax.persistence.PersistenceException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.edt.UnpublishReasonType;
import com.ericsson.oss.itpf.security.pki.cdps.notification.CRLAcknowledgementSender;
import com.ericsson.oss.itpf.security.pki.cdps.notification.events.CRLDistributionPointLocalServiceWrapper;
import com.ericsson.oss.itpf.security.pki.cdps.notification.events.UnpublishCRLEvent;
import com.ericsson.oss.itpf.security.pki.cdps.notification.events.validators.CACertificateInfoValidator;
import com.ericsson.oss.itpf.security.pki.cdps.notification.instrumentation.CRLInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.cdps.notification.setup.SetUpData;

/**
 * This class used to test UnpublishCRLEvent functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class UnpublishCRLEventTest extends SetUpData {

    @InjectMocks
    UnpublishCRLEvent unpublishCRLEvent;

    @Mock
    CRLAcknowledgementSender crlAcknowledgementSender;

    @Mock
    CACertificateInfoValidator caCertificateInfoValidator;

    @Mock
    private Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    CRLDistributionPointLocalServiceWrapper crlDistributionPointLocalServiceWrapper;
    
    @Mock
    CRLInstrumentationBean crlInstrumentationBean;
    
    public static final String ERR_CRL_INFO_EMPTY = "CRL Info list object is empty";
    private List<CACertificateInfo> caCertificateInfos;
    private List<CACertificateInfo> caCertificateInfosEmpty;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        caCertificateInfos = prepareCACertificateInfoList();

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.events.UnpublishCRLEvent#execute(java.util.List)} .
     */
    @Test
    public void testExecuteExpiredCACertificate() {

        unpublishCRLEvent.execute(caCertificateInfos, UnpublishReasonType.EXPIRED_CA_CERTIFICATE);

        Mockito.verify(caCertificateInfoValidator, times(1)).validate(caCertificateInfos);
        Mockito.verify(crlDistributionPointLocalServiceWrapper, times(1)).unPublishCRL(caCertificateInfos);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.events.UnpublishCRLEvent#execute(java.util.List)} .
     */
    @Test
    public void testExecuteRevokedCACertificate() {

        unpublishCRLEvent.execute(caCertificateInfos, UnpublishReasonType.REVOKED_CA_CERTIFICATE);

        Mockito.verify(caCertificateInfoValidator, times(1)).validate(caCertificateInfos);
        Mockito.verify(crlDistributionPointLocalServiceWrapper, times(1)).unPublishCRL(caCertificateInfos);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.events.UnpublishCRLEvent#execute(java.util.List)} .
     */
    @Test
    public void testExecuteThrowsCRLValidationException() {

        Mockito.doThrow(new CRLValidationException(ERR_CRL_INFO_EMPTY)).when(caCertificateInfoValidator).validate(caCertificateInfosEmpty);

        unpublishCRLEvent.execute(caCertificateInfosEmpty, UnpublishReasonType.REVOKED_CA_CERTIFICATE);

        Mockito.verify(caCertificateInfoValidator, times(1)).validate(caCertificateInfosEmpty);

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.events.UnpublishCRLEvent#execute(java.util.List)} .
     */
    @Test
    public void testExecuteThrowsPersistenceException() {

        Mockito.doThrow(new PersistenceException()).when(crlDistributionPointLocalServiceWrapper).unPublishCRL(caCertificateInfos);

        unpublishCRLEvent.execute(caCertificateInfos, UnpublishReasonType.EXPIRED_CA_CERTIFICATE);

        Mockito.verify(crlDistributionPointLocalServiceWrapper, times(1)).unPublishCRL(caCertificateInfos);

    }

}
