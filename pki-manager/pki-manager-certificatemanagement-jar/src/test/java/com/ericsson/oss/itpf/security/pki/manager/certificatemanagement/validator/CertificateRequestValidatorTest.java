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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator;

import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.CSR_ENCODING_FAILED;

import java.io.IOException;
import java.security.Security;

import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.*;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;

@RunWith(MockitoJUnitRunner.class)
public class CertificateRequestValidatorTest extends SetUPData {

    @InjectMocks
    CertificateRequestValidator csrValidator;

    @InjectMocks
    CertificateRequestValidator csrValidatormock;
    
    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;
    
    @Mock
    PKCS10CertificationRequest pKCS10CertificationRequest;
    

    private static SubjectAltNameSetUPData subjectAltNameData;

    static final String ENTITY_NAME = "Entity";
    static final String CHALLENGE_PASSWORD = "PKI";
    private static PKCS10CertificationRequestSetUPData pKCS10CertificationRequestSetUP;

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());  
    }

    /**
     * Prepares initial set up required to run the test cases.
     */
    @Before
    public void setup() {
        subjectAltNameData = new SubjectAltNameSetUPData();
        pKCS10CertificationRequestSetUP = new PKCS10CertificationRequestSetUPData();
    }

    /**
     * Method to test validation of subject in CSR.
     * 
     * @throws Exception
     */
    @Test
    public void testValidate_WithSubject() throws Exception {
        final X500Name x500Name = getSubject();

        final PKCS10CertificationRequest pKCS10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(x500Name, null);
        csrValidator.validate(pKCS10CertificationRequest);
    }

    /**
     * Method to test validation of SAN in CSR.
     * 
     * @throws Exception
     */
    @Test
    public void testValidate_WithSAN() throws Exception {
        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir7");

        final PKCS10CertificationRequest pkcs10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(subjectAltNameData.getGeneralNameList(csrSubjectAltName
                .getSubjectAltNameFields()));

        csrValidator.validate(pkcs10CertificationRequest);
    }
    

    /**
     * Method to test validation of CSR without subject and SAN.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testValidate_WithOut_SubjectAndSAN() throws Exception {
        final X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        final X500Name x500Name = builder.build();

        final PKCS10CertificationRequest pKCS10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(x500Name, null);

        csrValidator.validate(pKCS10CertificationRequest);
    }

    /**
     * Method to test validation of CSR in case of its signature is not proper.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testValidate_InvalidSignature_IOException() throws Exception {
        final X500Name x500Name = getSubject();

        final Attribute[] attribute = new Attribute[0];

        final PKCS10CertificationRequest pKCS10CertificationRequest = Mockito.mock(PKCS10CertificationRequest.class);

        Mockito.when(pKCS10CertificationRequest.getSubject()).thenReturn(x500Name);

        Mockito.when(pKCS10CertificationRequest.getAttributes()).thenReturn(attribute);
        Mockito.when(pKCS10CertificationRequest.getEncoded()).thenThrow(new IOException(CSR_ENCODING_FAILED));

        csrValidator.validate(pKCS10CertificationRequest);

    }

    /**
     * Method to get subject in X500Name form.
     * 
     * @return X500Name of the subject.
     */
    private X500Name getSubject() {
        final X500NameBuilder builder = new X500NameBuilder();
        builder.addRDN(BCStyle.CN, pKCS10CertificationRequestSetUP.ROOT_CA);
        final X500Name x500Name = builder.build();
        return x500Name;
    }
}