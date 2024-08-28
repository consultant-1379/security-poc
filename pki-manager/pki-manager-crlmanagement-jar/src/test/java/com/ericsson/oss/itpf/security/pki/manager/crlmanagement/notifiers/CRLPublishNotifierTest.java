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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.CRLEventNotificationService;

@RunWith(MockitoJUnitRunner.class)
public class CRLPublishNotifierTest {

    @InjectMocks
    CRLPublishNotifier cRLPublishNotifier;

    @Mock
    private CRLEventNotificationService crlEventNotificationService;

    @Mock
    private Logger logger;

    CACertificateIdentifier cACertificateIdentifier;
    List<CACertificateIdentifier> cACertificateIdentifierList;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        cACertificateIdentifier = new CACertificateIdentifier();
        cACertificateIdentifierList = new ArrayList<CACertificateIdentifier>();
        cACertificateIdentifierList.add(cACertificateIdentifier);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLPublishNotifier#notify(java.util.List)}.
     */
    @Test
    public void testNotifyListOfCACertificateIdentifier() {

        cRLPublishNotifier.notify(cACertificateIdentifierList);

        Mockito.verify(crlEventNotificationService).firePublishEvent(cACertificateIdentifierList);

    }

}
