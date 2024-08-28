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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.builders;

import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.builders.TDPServiceResponseEventBuilder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSResponseType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPServiceResponse;

@RunWith(MockitoJUnitRunner.class)
public class TDPServiceResponseEventBuilderTest {

    @InjectMocks
    TDPServiceResponseEventBuilder tdpserviceResponseEventBuilder;

    @Mock
    Certificate certificate;

    @Mock
    Map<String, List<Certificate>> trustMap;

    @Mock
    TDPSCertificateInfo tdpsCertificateInfo;

    private TDPSEntityType entityType = TDPSEntityType.CA_ENTITY;

    @Test
    public void testBuild() {

        tdpserviceResponseEventBuilder.entityType(entityType);
        tdpserviceResponseEventBuilder.trustMap(trustMap);

        TDPServiceResponse tdpserviceResponse = tdpserviceResponseEventBuilder.build();

        Assert.assertEquals(TDPSResponseType.SUCCESS, tdpserviceResponse.getResponseType());

    }

}
