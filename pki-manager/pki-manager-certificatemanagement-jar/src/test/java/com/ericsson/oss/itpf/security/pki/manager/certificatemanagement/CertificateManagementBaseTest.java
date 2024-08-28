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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.*;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

public class CertificateManagementBaseTest {

    /**
     * Assert expectedCertificate with actualCertificate.
     * 
     * @param expectedCertificate
     * @param actualCertificate
     */

    public void assertCertificate(final Certificate expectedCertificate, final Certificate actualCertificate) {

        assertNotNull(actualCertificate);

        assertEquals(expectedCertificate.getSerialNumber(), actualCertificate.getSerialNumber());
        assertEquals(expectedCertificate.getNotBefore(), actualCertificate.getNotBefore());
        assertEquals(expectedCertificate.getNotAfter(), actualCertificate.getNotAfter());
        assertEquals(expectedCertificate.getStatus(), actualCertificate.getStatus());
        assertEquals(expectedCertificate.getSubject(), actualCertificate.getSubject());
        assertEquals(expectedCertificate.getSubjectAltName(), actualCertificate.getSubjectAltName());

        assertEquals(expectedCertificate.getX509Certificate(), actualCertificate.getX509Certificate());

        assertEquals(expectedCertificate.getId(), actualCertificate.getId());
        assertEquals(expectedCertificate.getIssuedTime(), actualCertificate.getIssuedTime());
        assertEquals(expectedCertificate.getIssuer(), actualCertificate.getIssuer());

    }

    /**
     * Assert expectedEntityData with actualEntityData.
     * 
     * @param expectedEntityData
     * @param actualEntityData
     */
    public void assertEntityData(final EntityData expectedEntityData, final EntityData actualEntityData) {

        assertNotNull(actualEntityData);
        assertEquals(expectedEntityData.getId(), actualEntityData.getId());
        assertEquals(expectedEntityData.getEntityInfoData().getName(), actualEntityData.getEntityInfoData().getName());
    }

    /**
     * Assert expected certificateData with actual certificate.
     * 
     * @param certificateData
     * @param certificate
     * 
     */
    public void assertCertificate(final CertificateData certificateData, final Certificate certificate) {

        assertNotNull(certificate);
        //assertEquals(certificateData.getNotBefore(), certificate.getNotBefore());
        //assertEquals(certificateData.getNotAfter(), certificate.getNotAfter());
        //assertEquals(certificateData.getIssuedTime(), certificate.getIssuedTime());
        assertEquals(certificateData.getSerialNumber(), certificate.getSerialNumber());
        assertEquals(certificateData.getIssuerCA(), certificate.getIssuer());
        assertEquals(certificateData.getStatus().intValue(), certificate.getStatus().getId());
    }

    /**
     * Assert expected certificate with actual certificateData.
     * 
     * @param certificate
     * @param certificateData
     * @throws CertificateEncodingException
     */
    public void assertCertificateData(final Certificate certificate, final CertificateData certificateData) throws CertificateEncodingException {

        assertNotNull(certificateData);
        assertEquals(certificate.getSerialNumber(), certificateData.getSerialNumber());
        assertEquals(certificate.getNotBefore(), certificateData.getNotBefore());
        assertEquals(certificate.getNotAfter(), certificateData.getNotAfter());
        assertEquals(certificate.getStatus().getId(), certificateData.getStatus().intValue());
        assertEquals(certificate.getId(), certificateData.getId());

        if (certificate.getIssuer() != null) {
            assertEquals(certificate.getIssuer().getName(), certificateData.getIssuerCA().getCertificateAuthorityData().getName());
        }

        assertEquals(certificate.getSubject().toASN1String(), certificateData.getSubjectDN());
        assertTrue(Arrays.equals(certificate.getX509Certificate().getEncoded(), certificateData.getCertificate()));
    }

    /**
     * Assert expected certificateRequest with actual certificateRequestData.
     * 
     * @param certificateRequest
     * @param certificateRequestData
     * @throws CertificateEncodingException
     */
    public void assertCertificateRequestData(final CertificateRequest certificateRequest, final CertificateRequestData certificateRequestData) throws IOException {

        assertNotNull(certificateRequestData);
        if (certificateRequest.getCertificateRequestHolder() instanceof PKCS10CertificationRequestHolder) {

            final PKCS10CertificationRequestHolder pKCS10CertificationRequestHolder = (PKCS10CertificationRequestHolder) certificateRequest.getCertificateRequestHolder();
            assertTrue(Arrays.equals(pKCS10CertificationRequestHolder.getCertificateRequest().getEncoded(), certificateRequestData.getCsr()));

        } else {

            final CRMFRequestHolder crmfRequestHolder = (CRMFRequestHolder) certificateRequest.getCertificateRequestHolder();
            assertEquals(crmfRequestHolder.getCertificateRequest().getEncoded(), certificateRequestData.getCsr());

        }
        assertEquals(certificateRequest.getStatus().getId(), certificateRequestData.getStatus().intValue());

    }

    public void assertCertificateGenerationInfoData(final CertificateGenerationInfo certificateGenerationInfo, final CertificateGenerationInfoData certificateGenerationInfoData) {

        assertEquals(certificateGenerationInfo.getVersion(), certificateGenerationInfoData.getCertificateVersion());
        assertEquals(certificateGenerationInfo.getRequestType(), certificateGenerationInfoData.getRequestType());
        assertEquals(certificateGenerationInfo.getValidity().toString(), certificateGenerationInfoData.getValidity());
        assertEquals(certificateGenerationInfo.getCAEntityInfo().getName(), certificateGenerationInfoData.getcAEntityInfo().getCertificateAuthorityData().getName());

    }
}
