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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers;

import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.TDPSPublishStatusType;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.TDPSEventNotificationService;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

@RunWith(MockitoJUnitRunner.class)
public class TDPSUnpublishNotifierTest {

    @InjectMocks
    TDPSUnpublishNotifier tdpsUnpublishNotifier;

    @Mock
    TDPSEventNotificationService tDPSEventNotificationService;

    @Mock
    Logger logger;

    EntityType entityType;
    String entityName;
    List<Certificate> certificates;
    TDPSPublishStatusType tdpsStatus;

    @Before
    public void setUpData() {
        Certificate certificate = new Certificate();
        certificates = new ArrayList<Certificate>();
        certificates.add(certificate);
        entityType = EntityType.CA_ENTITY;
        tdpsStatus = TDPSPublishStatusType.UNPUBLISH;
    }

    @Test
    public void testNotifyList() throws CertificateEncodingException {
        tdpsUnpublishNotifier.notify(entityType, entityName, certificates);

        Mockito.verify(tDPSEventNotificationService).fireCertificateEvent(entityType, entityName, TDPSPublishStatusType.UNPUBLISH, certificates);

    }
}
