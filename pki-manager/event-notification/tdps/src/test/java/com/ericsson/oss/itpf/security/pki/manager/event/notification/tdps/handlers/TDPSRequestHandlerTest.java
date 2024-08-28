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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.handlers;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;

import javax.persistence.PersistenceException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.handlers.TDPSRequestHandler;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.sender.TDPServiceResponseEventSender;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.TrustDistributionLocalService;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

@RunWith(MockitoJUnitRunner.class)
public class TDPSRequestHandlerTest {

    @InjectMocks
    TDPSRequestHandler tdpsRequestHandler;

    @Mock
    TrustDistributionLocalService trustDistributionLocalService;

    @Mock
    Map<String, List<Certificate>> map;

    @Mock
    Logger logger;

    @Mock
    TDPServiceResponseEventSender tdpServiceResponseEventSenderForEntity;

    @Mock
    TDPServiceResponseEventSender tdpServiceResponseEventSenderForCAEntity;

    @Test
    public void testHandle() throws CertificateException, PersistenceException, IOException {
        final EntityType entityType = EntityType.ENTITY;

        Mockito.when(trustDistributionLocalService.getPublishedCertificates(entityType)).thenReturn(map);

        tdpsRequestHandler.handle();

        Mockito.verify(trustDistributionLocalService).getPublishedCertificates(entityType);

    }

    @Test
    public void testHandleCertificateException() throws CertificateException, PersistenceException, IOException {
        final EntityType entityType = EntityType.ENTITY;

        Mockito.when(trustDistributionLocalService.getPublishedCertificates(entityType)).thenThrow(new CertificateException());

        tdpsRequestHandler.handle();
        Mockito.verify(logger).warn("Error Occured while retriving certificates, not sending any response to pki-ra-tdps");

    }

}
