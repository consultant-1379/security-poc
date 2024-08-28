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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.*;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.PKCS10CertificationRequestSetUPData;

@RunWith(MockitoJUnitRunner.class)
public class CertificateRequestParserTest {

    @InjectMocks
    CertificateRequestParser cSRParser;

    private static PKCS10CertificationRequestSetUPData pKCS10CertificationRequestSetUP;

    /**
     * Prepares initial set up required to run the test cases.
     * 
     * @throws Exception
     */
    @BeforeClass
    public static void setUpBeforeClass() { 
        pKCS10CertificationRequestSetUP = new PKCS10CertificationRequestSetUPData();
    }

    public CertificateRequest getCSRWithPKCS10Req(final PKCS10CertificationRequest pkcs10CertificationRequest) throws IOException {

        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pkcs10CertificationRequest);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(pkcs10CertificationRequestHolder);
        return certificateRequest;
    }

    public CertificateRequest getCSRWithCRMFReq(final CertificateRequestMessage certificateRequestMessage) throws IOException {
        final CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);
        return certificateRequest;
    }

    /**
     * Method to test extraction of SubjectAltNameValues object from CSR.
     * 
     * @throws Exception
     */
    @Test
    public void testExtractSubjectAltNameValues() throws Exception {

        final PKCS10CertificationRequest pKCS10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Requestwithattributes();
        final CertificateRequest certificateRequest = getCertificateRequest(pKCS10CertificationRequest);

        final SubjectAltName subjectAltName = CertificateRequestParser.extractSubjectAltName(certificateRequest);

        assertNotNull(subjectAltName);
        assertNotNull(subjectAltName.getSubjectAltNameFields());
        assertEquals(8, subjectAltName.getSubjectAltNameFields().size());
    }

    private CertificateRequest getCertificateRequest(final PKCS10CertificationRequest pKCS10CertificationRequest) throws NoSuchAlgorithmException, SignatureException, IOException,
            InvalidKeyException, NoSuchProviderException, OperatorCreationException {

        final CertificateRequest certificateRequest = new CertificateRequest();
        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pKCS10CertificationRequest);
        certificateRequest.setCertificateRequestHolder(pkcs10CertificationRequestHolder);
        return certificateRequest;
    }

    /**
     * Method to test extraction of SubjectAltNameValues object from CSR in case it is absent in CSR.
     * 
     * @throws Exception
     */
    @Test
    public void testExtractSubjectAltNameValues_WithOutSAN() throws Exception {

        final X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        final X500Name x500Name = builder.build();

        final PKCS10CertificationRequest pKCS10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(x500Name, null);
        final CertificateRequest certificateRequest = getCertificateRequest(pKCS10CertificationRequest);

        final SubjectAltName subjectAltName = CertificateRequestParser.extractSubjectAltName(certificateRequest);

        assertNull(subjectAltName);
    }

    /**
     * Method to test check of SubjectAltName in CSR.
     * 
     * @throws Exception
     */
    @Test
    public void testCheckForSubjectAltName() throws Exception {

        final PKCS10CertificationRequest pKCS10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Requestwithattributes();
        final boolean subjectAltNameExists = CertificateRequestParser.checkForSubjectAltName(pKCS10CertificationRequest);
        assertTrue(subjectAltNameExists);

    }

    /**
     * Method to test check of SubjectAltName in CSR when it does not exist.
     * 
     * @throws Exception
     */
    @Test
    public void testCheckForSubjectAltName_NotExists() throws Exception {

        final X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        final X500Name x500Name = builder.build();

        final PKCS10CertificationRequest pKCS10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(x500Name, null);

        final boolean subjectAltNameExists = CertificateRequestParser.checkForSubjectAltName(pKCS10CertificationRequest);
        assertFalse(subjectAltNameExists);

    }

    /**
     * Method to test extraction of key generation algorithm from the CSR.
     * 
     * @throws Exception
     */
    @Test
    public void testExtractKeyGenerationAlgorithm() throws Exception {

        final PKCS10CertificationRequest pKCS10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10RequestWithChallengePassword();
        final CertificateRequest certificateRequest = getCertificateRequest(pKCS10CertificationRequest);

        final String KeyGenerationAlgorithm = CertificateRequestParser.extractKeyGenerationAlgorithm(certificateRequest);

        assertNotNull(KeyGenerationAlgorithm);
        assertEquals(pKCS10CertificationRequestSetUP.KEY_GEN_ALGORITHM, KeyGenerationAlgorithm);
    }

}