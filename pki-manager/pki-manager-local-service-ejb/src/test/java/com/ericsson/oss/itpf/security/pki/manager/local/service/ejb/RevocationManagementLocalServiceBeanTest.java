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
package com.ericsson.oss.itpf.security.pki.manager.local.service.ejb;

import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.RevocationManager;

@RunWith(MockitoJUnitRunner.class)
public class RevocationManagementLocalServiceBeanTest {

    @InjectMocks
    RevocationManagementLocalServiceBean revocationManagementLocalServiceBean;

    @Mock
    RevocationManager revocationManager;

    @Mock
    ContextUtility contextUtility;

    private static final String caName = "ENM_RootCA";
    private static final String cerficateSerialNumber = "1508f262d31";

    private CertificateIdentifier certificateIdentifier;
    private Date invalidityDate;

    @Before
    public void setUpData() {
        certificateIdentifier = new CertificateIdentifier();
        certificateIdentifier.setIssuerName(caName);
        certificateIdentifier.setSerialNumber(cerficateSerialNumber);
        invalidityDate = new Date();
    }

    @Test
    public void testRevokeCertificate() {
        revocationManagementLocalServiceBean.revokeCertificate(certificateIdentifier, invalidityDate, RevocationReason.UNSPECIFIED, "", "");
    }
}
