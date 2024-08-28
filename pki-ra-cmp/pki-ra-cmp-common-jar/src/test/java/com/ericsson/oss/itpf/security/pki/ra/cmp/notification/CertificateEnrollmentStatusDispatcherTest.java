/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.cmp.notification;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.CertificateEnrollmentStatusDispatcher;
import com.ericsson.oss.itpf.security.pki.ra.model.events.CertificateEnrollmentStatus;

@RunWith(MockitoJUnitRunner.class)
public class CertificateEnrollmentStatusDispatcherTest {

    @InjectMocks
    CertificateEnrollmentStatusDispatcher certificateEnrollmentStatusDispatcher;

    @Mock
    Logger logger;

    @Mock
    private EventSender<CertificateEnrollmentStatus> certificateEnrollmentSender;

    @Test
    public void testDispatch() {
        final CertificateEnrollmentStatus certificateEnrollmentStatus = new CertificateEnrollmentStatus();
        certificateEnrollmentStatusDispatcher.dispatch(certificateEnrollmentStatus);
        Mockito.verify(certificateEnrollmentSender).send(certificateEnrollmentStatus);
    }

}
