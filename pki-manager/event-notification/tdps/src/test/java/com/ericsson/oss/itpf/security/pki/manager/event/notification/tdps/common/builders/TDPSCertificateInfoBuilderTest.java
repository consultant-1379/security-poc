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

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.builders.TDPSCertificateInfoBuilder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSCertificateStatusType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType;

@RunWith(MockitoJUnitRunner.class)
public class TDPSCertificateInfoBuilderTest {

    @InjectMocks
    TDPSCertificateInfoBuilder tdpsCertificateInfoBuilder;

    @Test
    public void testBuild() {

        setupData();

        TDPSCertificateInfo tDPSCertificateInfo = tdpsCertificateInfoBuilder.build();
        Assert.assertEquals(TDPSCertificateStatusType.ACTIVE, tDPSCertificateInfo.getTdpsCertificateStatusType());

    }

    public void setupData() {
        final byte[] certificate = new byte[] { 1 };
        final String serialNumber = "sdgt5y67hg";
        final String entityName = "end_entity";
        final TDPSCertificateStatusType certificateStatusType = TDPSCertificateStatusType.ACTIVE;
        final TDPSEntityType entityType = TDPSEntityType.ENTITY;
        final String issuerName = "RootCA";

        tdpsCertificateInfoBuilder.certificate(certificate);
        tdpsCertificateInfoBuilder.serialNumber(serialNumber);
        tdpsCertificateInfoBuilder.entityName(entityName);
        tdpsCertificateInfoBuilder.entityType(entityType);
        tdpsCertificateInfoBuilder.tDPSCertificateStatusType(certificateStatusType);
        tdpsCertificateInfoBuilder.issuerName(issuerName);

    }

}
