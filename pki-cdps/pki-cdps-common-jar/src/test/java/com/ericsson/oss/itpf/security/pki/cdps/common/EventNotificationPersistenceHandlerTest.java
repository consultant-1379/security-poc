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
package com.ericsson.oss.itpf.security.pki.cdps.common;

import java.util.LinkedList;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;
import com.ericsson.oss.itpf.security.pki.cdps.common.EventNotificationPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper.CACertificateInfoMapper;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper.CRLInfoMapper;

/**
 * This class used to test EventNotificationPersistenceHandler functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class EventNotificationPersistenceHandlerTest {

    @InjectMocks
    EventNotificationPersistenceHandler eventNotificationPersistenceHandler;

    @Mock
    private CACertificateInfoMapper caCertificateInfoMapper;

    @Mock
    private CRLInfoMapper crlInfoMapper;

    @Mock
    private Logger logger;

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.common.EventNotificationPersistenceHandler#publishCRL(java.util.List)} .
     */
    @Test
    public void testPublishCRL() {
        eventNotificationPersistenceHandler.publishCRL(new LinkedList<CRLInfo>());
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.common.EventNotificationPersistenceHandler#publishCRL(java.util.List)} .
     */
    @Test
    public void testPublishCRLThrowsCRLDistributionPointServiceException() {

        eventNotificationPersistenceHandler.publishCRL(new LinkedList<CRLInfo>());

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.common.EventNotificationPersistenceHandler#unPublishCRL(java.util.List)} .
     */
    @Test
    public void testUnPublishCRL() {

        eventNotificationPersistenceHandler.unPublishCRL(new LinkedList<CACertificateInfo>());

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.common.EventNotificationPersistenceHandler#unPublishCRL(java.util.List)} .
     */
    @Test
    public void testUnPublishCRLThrowsCRLDistributionPointServiceException() {

        eventNotificationPersistenceHandler.unPublishCRL(new LinkedList<CACertificateInfo>());
    }

}
