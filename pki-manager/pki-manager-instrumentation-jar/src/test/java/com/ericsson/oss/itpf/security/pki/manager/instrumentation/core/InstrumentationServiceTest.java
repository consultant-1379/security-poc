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
package com.ericsson.oss.itpf.security.pki.manager.instrumentation.core;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricGroup;

@RunWith(MockitoJUnitRunner.class)
public class InstrumentationServiceTest {

    @InjectMocks
    InstrumentationServiceFactory instrumentationServiceFactory;

    @Mock
    InstrumentationService entityManagementInstrumentationService;

    @Mock
    InstrumentationService caCertificateManagementInstrumentationService;

    @Mock
    InstrumentationService entityCertificateManagementInstrumentationService;

    @Mock
    InstrumentationService crlManagementInstrumentationService;

    @Mock
    InstrumentationService revocationManagementInstrumentationService;

    @Test
    public void testEntityManagementInstrumentationService() {

        assertEquals(instrumentationServiceFactory.getInstrumentationService(MetricGroup.ENTITYMGMT), entityManagementInstrumentationService);
    }

    @Test
    public void testCACertificateManagementInstrumentationService() {

        assertEquals(instrumentationServiceFactory.getInstrumentationService(MetricGroup.CACERTIFICATEMGMT), caCertificateManagementInstrumentationService);
    }

    @Test
    public void testEntityCertificateManagementInstrumentationService() {

        assertEquals(instrumentationServiceFactory.getInstrumentationService(MetricGroup.ENTITYCERTIFICATEMGMT), entityCertificateManagementInstrumentationService);
    }

    @Test
    public void testCRLManagementInstrumentationService() {

        assertEquals(instrumentationServiceFactory.getInstrumentationService(MetricGroup.CRLMGMT), crlManagementInstrumentationService);
    }

    @Test
    public void testRevocationManagementInstrumentationService() {

        assertEquals(instrumentationServiceFactory.getInstrumentationService(MetricGroup.REVOCATIONMGMT), revocationManagementInstrumentationService);
    }

}