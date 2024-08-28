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
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLDistributionPointServiceException;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;
import com.ericsson.oss.itpf.security.pki.cdps.notification.CRLAcknowledgementSender;
import com.ericsson.oss.itpf.security.pki.cdps.notification.events.CRLDistributionPointLocalServiceWrapper;
import com.ericsson.oss.itpf.security.pki.cdps.notification.events.PublishCRLEvent;
import com.ericsson.oss.itpf.security.pki.cdps.notification.events.validators.CRLInfoValidator;
import com.ericsson.oss.itpf.security.pki.cdps.notification.instrumentation.CRLInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.cdps.notification.setup.SetUpData;

/**
 * This class used to test PublishCRLEvent functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class PublishCRLEventTest extends SetUpData {

    @InjectMocks
    PublishCRLEvent publishCRLEvent;

    @Mock
    CRLAcknowledgementSender crlAcknowledgementSender;

    @Mock
    CRLInfoValidator crlInfoValidator;

    @Mock
    private Logger logger;

    @Mock
    CRLDistributionPointLocalServiceWrapper crlDistributionPointLocalServiceWrapper;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    CRLInstrumentationBean crlInstrumentationBean;

    public static final String ERR_CRL_INFO_EMPTY = "CRL Info list object is empty";
    
    private List<CRLInfo> crlInfoList;
    private List<CRLInfo> crlInfoListEmpty;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        crlInfoList = prepareCRLInfoList();

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.events.PublishCRLEvent#execute(java.util.List)} .
     */
    @Test
    public void testExecute() {

        publishCRLEvent.execute(crlInfoList);

        Mockito.verify(crlInfoValidator, times(1)).validate(crlInfoList);

        Mockito.verify(crlDistributionPointLocalServiceWrapper, times(1)).publishCRL(crlInfoList);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.events.PublishCRLEvent#execute(java.util.List)} .
     */
    @Test
    public void testExecuteThrowsCRLValidationException() {
        Mockito.doThrow(new CRLValidationException(ERR_CRL_INFO_EMPTY)).when(crlInfoValidator).validate(crlInfoListEmpty);

        publishCRLEvent.execute(crlInfoListEmpty);

        Mockito.verify(crlInfoValidator, times(1)).validate(crlInfoListEmpty);

    }

    @Test
    public void testExecuteThrowsPersistenceException() {

        Mockito.doThrow(new PersistenceException()).when(crlDistributionPointLocalServiceWrapper).publishCRL(crlInfoList);

        publishCRLEvent.execute(crlInfoList);

        Mockito.verify(crlDistributionPointLocalServiceWrapper, times(1)).publishCRL(crlInfoList);
    }

    @Test
    public void testExecuteThrowsCRLDistributionPointServiceException() {

        Mockito.doThrow(new CRLDistributionPointServiceException("Error while persisting data")).when(crlDistributionPointLocalServiceWrapper).publishCRL(crlInfoList);

        publishCRLEvent.execute(crlInfoList);

        Mockito.verify(crlDistributionPointLocalServiceWrapper, times(1)).publishCRL(crlInfoList);
    }

}
