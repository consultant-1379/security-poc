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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.*;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.ExternalCRLInfoData;

@RunWith(MockitoJUnitRunner.class)
public class CRLMapperTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityMapper.class);

    @InjectMocks
    ExternalCRLMapper crlMapper;

    ExternalCRLInfo externalCrl;
    ExternalCRLInfoData externalCrlInfoData;

    @Before
    public void setup() throws IOException, CRLException {
        fillCrl();
        fillCrlData();
    }

    /**
     * @throws IOException
     * @throws CRLException
     * 
     */
    private void fillCrlData() throws IOException, CRLException {
        externalCrlInfoData = new ExternalCRLInfoData();
        externalCrlInfoData.setAutoUpdate(true);
        externalCrlInfoData.setAutoUpdateCheckTimer(0);
        externalCrlInfoData.setNextUpdate(new Date());
        externalCrlInfoData.setUpdateUrl("url");
        final X509CRLHolder x509CRL = externalCrl.getX509CRL();

        externalCrlInfoData.setCrl(x509CRL.retrieveCRL().getEncoded());

    }

    /**
     * 
     */
    private void fillCrl() {
        externalCrl = new ExternalCRLInfo();
        externalCrl.setAutoUpdate(true);
        externalCrl.setAutoUpdateCheckTimer(0);
        externalCrl.setNextUpdate(new Date());
        externalCrl.setUpdateURL("url");
        try {
            externalCrl.setX509CRL(getCRL("certificates/testCA.crl"));
        } catch (IOException | CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private X509CRLHolder getCRL(final String filename) throws IOException, CertificateException {
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(filename);
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        try {
            final X509CRL crl = (X509CRL) certificateFactory.generateCRL(inputStream);
            return new X509CRLHolder(crl.getEncoded());
        } catch (final CRLException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Test
    public void testToAPIModel() throws Exception {

        final ExternalCRLInfo crlTest = crlMapper.toAPIFromModel(externalCrlInfoData);
        assertEquals(externalCrlInfoData.isAutoUpdate(), crlTest.isAutoUpdate());
        assertEquals(externalCrlInfoData.getNextUpdate(), crlTest.getNextUpdate());
    }

    @Test
    public void testFromAPiModel() {
        final ExternalCRLInfoData crlDataTest = crlMapper.fromAPIToModel(externalCrl);

        assertEquals(externalCrl.isAutoUpdate(), crlDataTest.isAutoUpdate());
        assertEquals(externalCrl.getNextUpdate(), crlDataTest.getNextUpdate());
    }
}
