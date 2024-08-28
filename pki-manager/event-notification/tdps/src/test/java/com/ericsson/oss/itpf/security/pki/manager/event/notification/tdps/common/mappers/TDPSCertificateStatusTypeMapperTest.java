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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.mappers;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.mappers.TDPSCertificateStatusTypeMapper;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSCertificateStatusType;

@RunWith(MockitoJUnitRunner.class)
public class TDPSCertificateStatusTypeMapperTest {

    @InjectMocks
    TDPSCertificateStatusTypeMapper tdpsCertificateStatusTypeMapper;

    @Mock
    Logger logger;

    @Test
    public void testToModel() {

        final CertificateStatus certificateStatus = CertificateStatus.EXPIRED;
        tdpsCertificateStatusTypeMapper.toModel(certificateStatus);
        Assert.assertEquals(CertificateStatus.EXPIRED, certificateStatus);
    }

    @Test
    public void testToModelActive() {

        final CertificateStatus certificateStatus = CertificateStatus.ACTIVE;

        tdpsCertificateStatusTypeMapper.toModel(certificateStatus);
        Assert.assertEquals(CertificateStatus.ACTIVE, certificateStatus);
    }

    @Test
    public void testToModelInActive() {

        final CertificateStatus certificateStatus = CertificateStatus.INACTIVE;
        tdpsCertificateStatusTypeMapper.toModel(certificateStatus);

        Assert.assertEquals(CertificateStatus.INACTIVE, certificateStatus);
    }

    @Test
    public void testFromModelActive() {

        final TDPSCertificateStatusType tdpsCertificateStatusType = TDPSCertificateStatusType.ACTIVE;

        tdpsCertificateStatusTypeMapper.fromModel(tdpsCertificateStatusType);
        Assert.assertEquals(TDPSCertificateStatusType.ACTIVE, tdpsCertificateStatusType);
    }

    @Test
    public void testFromModelInActive() {

        final TDPSCertificateStatusType tdpsCertificateStatusType = TDPSCertificateStatusType.INACTIVE;

        tdpsCertificateStatusTypeMapper.fromModel(tdpsCertificateStatusType);
        Assert.assertEquals(TDPSCertificateStatusType.INACTIVE, tdpsCertificateStatusType);
    }

    @Test
    public void testFromModel() {

        final TDPSCertificateStatusType tdpsCertificateStatusType = TDPSCertificateStatusType.UNKNOWN;

        tdpsCertificateStatusTypeMapper.fromModel(tdpsCertificateStatusType);
        Assert.assertEquals(TDPSCertificateStatusType.UNKNOWN, tdpsCertificateStatusType);
    }

}
