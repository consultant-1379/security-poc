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
package com.ericsson.oss.itpf.security.pki.manager.local.service.ejb;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.common.helpers.CRLHelper;

@RunWith(MockitoJUnitRunner.class)
public class CRLManagementLocalServiceBeanTest {

    @InjectMocks
    CRLManagementLocalServiceBean crlManagementLocalServiceBean;

    @Mock
    Logger logger;

    @Mock
    private CRLHelper crlHelper;

    @Test
    public void testUpdateCRLStatus() {
        final List<CACertificateIdentifier> caCertificateIdentifiers = new ArrayList<CACertificateIdentifier>();
        final CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier("CAName", "SerialNumber");
        caCertificateIdentifiers.add(caCertificateIdentifier);
        final boolean isPublishedToCDPS = true;

        final CRLInfo crlInfo = new CRLInfo();
        when(crlHelper.getCRLByCACertificate(caCertificateIdentifier, false, false)).thenReturn(crlInfo);

        doNothing().when(crlHelper).updateCRLStatus(crlInfo);

        crlManagementLocalServiceBean.updateCRLPublishUnpublishStatus(caCertificateIdentifiers, isPublishedToCDPS);

        verify(crlHelper, times(1)).updateCRLStatus(crlInfo);
    }

    @Test
    public void testGetCRLByCACertificateIdentifier() {
        final CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();

        final CRLInfo crlInfo = new CRLInfo();
        crlInfo.setId(234);
        when(crlHelper.getCRLByCACertificate(caCertificateIdentifier, false, false)).thenReturn(crlInfo);

        assertEquals(crlInfo.getId(), crlManagementLocalServiceBean.getCRLByCACertificateIdentifier(caCertificateIdentifier).getId());
    }

    @Test
    public void testDeleteInvalidCRLs() {
        final String debugMsg = "deleteInvalidCRLs Method in CRLManagementLocalServiceBean class";
        final CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
        List<CACertificateIdentifier> caCertificateIdentifiers = new ArrayList<CACertificateIdentifier>();
        caCertificateIdentifiers.add(caCertificateIdentifier);

        crlManagementLocalServiceBean.deleteInvalidCRLs(caCertificateIdentifiers);
        verify(crlHelper).deleteInvalidCRLs(caCertificateIdentifiers);
        verify(logger, times(1)).debug(debugMsg);
    }

    @Test
    public void testGetAllPublishCRLs() {
        crlManagementLocalServiceBean.getAllPublishCRLs();
        verify(crlHelper).getCRLsForPublishOnStartup();
    }

    @Test
    public void testGetAllUnPublishCRLs() {
        crlManagementLocalServiceBean.getAllUnPublishCRLs();
        verify(crlHelper).getCRLsForUnpublishOnStartup();
    }
}
