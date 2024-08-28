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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.ejb;

import static org.mockito.Mockito.verify;

import java.util.Date;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.RevocationManager;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;

@RunWith(MockitoJUnitRunner.class)
public class RevocationServiceBeanTest {

    @InjectMocks
    RevocationServiceBean revocationServiceBean;

    @Mock
    Logger logger;

    @Mock
    RevocationManager revocationManager;

    @Test
    public void testRevokeCAEntityCertificates() {
        final String entityName = "entityName";
        final RevocationReason revocationReason = RevocationReason.AFFILIATION_CHANGED;
        final Date invalidityDate = new Date();

        revocationServiceBean.revokeCAEntityCertificates(entityName, revocationReason, invalidityDate);

        verify(revocationManager).revokeCAEntityCertificates(entityName, revocationReason, invalidityDate);
    }

    @Test
    public void testRevokeCertificateByDN() {
        final RevocationReason revocationReason = RevocationReason.AFFILIATION_CHANGED;
        final Date invalidityDate = new Date();
        final DNBasedCertificateIdentifier dnBasedCertificateIdentifier = new DNBasedCertificateIdentifier();

        revocationServiceBean.revokeCertificateByDN(dnBasedCertificateIdentifier, revocationReason, invalidityDate);

        verify(revocationManager).revokeCertificateByDN(dnBasedCertificateIdentifier, revocationReason, invalidityDate);
    }

    @Test
    public void testRevokeCertificateByIssuerName() {
        final RevocationReason revocationReason = RevocationReason.AFFILIATION_CHANGED;
        final Date invalidityDate = new Date();
        final CertificateIdentifier certificateIdentifier = new CertificateIdentifier();

        revocationServiceBean.revokeCertificateByIssuerName(certificateIdentifier, revocationReason, invalidityDate);

        verify(revocationManager).revokeCertificateByIssuerName(certificateIdentifier, revocationReason, invalidityDate);
    }

    @Test
    public void testRevokeEntityCertificates() {
        final String entityName = "entityName";
        final RevocationReason revocationReason = RevocationReason.AFFILIATION_CHANGED;
        final Date invalidityDate = new Date();

        revocationServiceBean.revokeEntityCertificates(entityName, revocationReason, invalidityDate);

        verify(revocationManager).revokeEntityCertificates(entityName, revocationReason, invalidityDate);
    }

}
