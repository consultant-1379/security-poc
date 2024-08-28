/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.builders;

import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.builders.TDPSCertificateEventBuilder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSOperationType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSCertificateEvent;

@RunWith(MockitoJUnitRunner.class)
public class TDPSCertificateEventBuilderTest {

    @InjectMocks
    TDPSCertificateEventBuilder tdpsCertificateEventBuilder;

    @Mock
    TDPSCertificateInfo tdpsCertificateInfo;

    @Test
    public void testBuild() {
        setupData();
        TDPSCertificateEvent tdpsCertificateEvent = tdpsCertificateEventBuilder.build();
        Assert.assertEquals(TDPSOperationType.PUBLISH, tdpsCertificateEvent.getTdpsOperationType());

    }

    public void setupData() {
        final TDPSOperationType publishType = TDPSOperationType.PUBLISH;
        final List<TDPSCertificateInfo> tdpsCertificateInfos = new ArrayList<TDPSCertificateInfo>();
        tdpsCertificateInfos.add(tdpsCertificateInfo);

        tdpsCertificateEventBuilder.publishType(publishType);
        tdpsCertificateEventBuilder.tDPSCertificateInfo(tdpsCertificateInfos);

    }

}
