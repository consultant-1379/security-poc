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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.override;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.List;

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
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;

@RunWith(MockitoJUnitRunner.class)
public class SubjectOverriderTest {

    @InjectMocks
    SubjectOverrider subjectOverrider;

    @Mock
    Logger logger;

    private static SubjectSetUPData subjectData;
    private static PKCS10CertificationRequestSetUPData pKCS10CertificationRequestSetUP;
    private static CertificateRequestMessageSetUPData certificateRequestMessageSetUP;

    private static final String OVERRIDING_OPERATOR = "?";
    private static final String ORGANIZATION = "Ericsson";
    private static final String INVALID_COMMON_NAME = "CN=/,OU=TCS";
    private static final String INVALID_DC = "DC=TestDC1\\,TestDC2";
    private static final String INVALID_ORGANIZATION_UNIT = "CN=PKI,OU=P/KICo\\re";
    private static final String INVALID_SUBJECT = "CN=PK\"I,OU=PKICo\"re";

    @BeforeClass
    public static void setup() {

        subjectData = new SubjectSetUPData();
        pKCS10CertificationRequestSetUP = new PKCS10CertificationRequestSetUPData();
        certificateRequestMessageSetUP = new CertificateRequestMessageSetUPData();
    }

    private SubjectField getSubjectField(final SubjectFieldType subjectFieldType, final String subjectFieldValue) {

        final SubjectField subjectField = new SubjectField();
        subjectField.setType(subjectFieldType);
        subjectField.setValue(subjectFieldValue);

        return subjectField;

    }

    /**
     * 
     * entity : CN=?,OU=PKI,O=Ericsson CSR : CN=TestCA Output : CN=TestCA,OU=PKI,O=Ericsson
     * 
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws IOException
     */

    @Test
    public void testOverrideSubject1() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {

        final Subject entitySubject = subjectData.getSubject_v1("?", "PKI", "TestDC");
        final PKCS10CertificationRequest pkcs10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(new X500Name("CN=TestCA"), null);
        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pkcs10CertificationRequest);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(pkcs10CertificationRequestHolder);

        final Subject actualSubject = subjectOverrider.overrideSubject(entitySubject, certificateRequest);

        final Subject expectedSubject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.COMMON_NAME, "TestCA"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION_UNIT, "PKI"));
        subjectFields.add(getSubjectField(SubjectFieldType.DC, "TestDC"));
        expectedSubject.setSubjectFields(subjectFields);

        assertEquals(expectedSubject, actualSubject);

    }

    /**
     * 
     * entity : CN=?,OU=PKI,O=Ericsson Output : OU=PKI,O=Ericsson
     * 
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws IOException
     */

    @Test
    public void testOverrideSubject2() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {

        final Subject entitySubject = subjectData.getSubject("?", "PKI", "Ericsson");

        final X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        final X500Name name = builder.build();

        final PKCS10CertificationRequest pkcs10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(name, "dir1");
        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pkcs10CertificationRequest);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(pkcs10CertificationRequestHolder);

        final Subject actualSubject = subjectOverrider.overrideSubject(entitySubject, certificateRequest);

        final Subject expectedSubject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION_UNIT, "PKI"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION, "Ericsson"));
        expectedSubject.setSubjectFields(subjectFields);

        assertEquals(expectedSubject, actualSubject);

    }

    /**
     * 
     * entity : CN=?,OU=PKI,O=Ericsson CSR:CN=TestCA,OU=PKICore,O=TCS Output : CN=TestCA,OU=PKI,O=Ericsson
     * 
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws IOException
     */

    @Test
    public void testOverrideSubject3() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {

        final Subject entitySubject = subjectData.getSubject("?", "PKI", "Ericsson");
        final PKCS10CertificationRequest pkcs10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(new X500Name("CN=TestCA,OU=PKICore,O=TCS"), null);

        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pkcs10CertificationRequest);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(pkcs10CertificationRequestHolder);

        final Subject actualSubject = subjectOverrider.overrideSubject(entitySubject, certificateRequest);

        final Subject expectedSubject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.COMMON_NAME, "TestCA"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION_UNIT, "PKI"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION, "Ericsson"));
        expectedSubject.setSubjectFields(subjectFields);

        assertEquals(expectedSubject, actualSubject);

    }

    /**
     * 
     * entity : CN=?,OU=?,O=Ericsson CSR:CN=TestCA,OU=PKICore Output : CN=TestCA,OU=PKICore,O=Ericsson
     * 
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws IOException
     */

    @Test
    public void testOverrideSubject4() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {

        final Subject entitySubject = subjectData.getSubject("?", "?", "Ericsson");
        final PKCS10CertificationRequest pkcs10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(new X500Name("CN=TestCA,OU=PKICore"), null);

        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pkcs10CertificationRequest);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(pkcs10CertificationRequestHolder);

        final Subject actualSubject = subjectOverrider.overrideSubject(entitySubject, certificateRequest);

        final Subject expectedSubject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.COMMON_NAME, "TestCA"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION_UNIT, "PKICore"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION, "Ericsson"));
        expectedSubject.setSubjectFields(subjectFields);

        assertEquals(expectedSubject, actualSubject);

    }

    /**
     * 
     * entity : CN=?,OU=?,O=Ericsson Output : O=Ericsson
     * 
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws IOException
     */

    @Test
    public void testOverrideSubject5() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {

        final Subject entitySubject = subjectData.getSubject("?", "?", "Ericsson");
        final X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        final X500Name name = builder.build();

        final PKCS10CertificationRequest pkcs10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(name, "dir1");

        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pkcs10CertificationRequest);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(pkcs10CertificationRequestHolder);

        final Subject actualSubject = subjectOverrider.overrideSubject(entitySubject, certificateRequest);

        final Subject expectedSubject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION, "Ericsson"));
        expectedSubject.setSubjectFields(subjectFields);

        assertEquals(expectedSubject, actualSubject);

    }

    /**
     * 
     * entity : CN=?,OU=?,O=Ericsson CSR: CN=TestCA,OU=PKICore,O=TCS Output : CN=TestCA,OU=Security,O=Ericsson
     * 
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws IOException
     */

    @Test
    public void testOverrideSubject6() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {

        final Subject entitySubject = subjectData.getSubject("?", "?", "Ericsson");
        final PKCS10CertificationRequest pkcs10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(new X500Name("CN=TestCA,OU=PKICore,O=TCS"), null);

        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pkcs10CertificationRequest);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(pkcs10CertificationRequestHolder);

        final Subject actualSubject = subjectOverrider.overrideSubject(entitySubject, certificateRequest);

        final Subject expectedSubject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.COMMON_NAME, "TestCA"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION_UNIT, "PKICore"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION, "Ericsson"));
        expectedSubject.setSubjectFields(subjectFields);

        assertEquals(expectedSubject, actualSubject);

    }

    /**
     * 
     * entity : CN=?,OU=?,O=? CSR: CN=TestCA,OU=PKICore,O=TCS Output : CN=TestCA,OU=PKICore,O=TCS
     * 
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws IOException
     */

    @Test
    public void testOverrideSubject7() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {

        final Subject entitySubject = subjectData.getSubject("?", "?", "?");

        final PKCS10CertificationRequest pkcs10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(new X500Name("CN=TestCA,OU=PKICore,O=TCS"), null);

        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pkcs10CertificationRequest);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(pkcs10CertificationRequestHolder);

        final Subject actualSubject = subjectOverrider.overrideSubject(entitySubject, certificateRequest);

        final Subject expectedSubject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.COMMON_NAME, "TestCA"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION_UNIT, "PKICore"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION, "TCS"));
        expectedSubject.setSubjectFields(subjectFields);

        assertEquals(expectedSubject, actualSubject);

    }

    /**
     * 
     * entity : CN=?,OU=?,O=? Output : empty
     * 
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws IOException
     */
    @Test
    public void testOverrideSubject8() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {

        final Subject entitySubject = subjectData.getSubject("?", "?", "?");

        final X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        final X500Name name = builder.build();

        final PKCS10CertificationRequest pkcs10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(name, "dir1");

        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pkcs10CertificationRequest);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(pkcs10CertificationRequestHolder);

        final Subject actualSubject = subjectOverrider.overrideSubject(entitySubject, certificateRequest);

        assertTrue(actualSubject.getSubjectFields().isEmpty());

    }

    /**
     * 
     * entity : CN=?,OU=PKI,O=Ericsson CSR : CN=TestCA Output : CN=TestCA,OU=PKI,O=Ericsson
     * 
     * @throws OperatorCreationException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */

    @Test
    public void testOverrideSubject1_forCRMF() throws NoSuchAlgorithmException, OperatorCreationException, IOException {

        final Subject entitySubject = subjectData.getSubject("?", "PKI", "Ericsson");
        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUP.generateCRMFRequest(new X500Name("CN=TestCA"), null);
        final CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);

        final Subject actualSubject = subjectOverrider.overrideSubject(entitySubject, certificateRequest);

        final Subject expectedSubject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.COMMON_NAME, "TestCA"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION_UNIT, "PKI"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION, "Ericsson"));
        expectedSubject.setSubjectFields(subjectFields);

        assertEquals(expectedSubject, actualSubject);

    }

    /**
     * 
     * entity : CN=?,OU=PKI,O=Ericsson Output : OU=PKI,O=Ericsson
     * 
     * @throws OperatorCreationException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */

    @Test
    public void testOverrideSubject2_forCRMF() throws NoSuchAlgorithmException, OperatorCreationException, IOException {

        final Subject entitySubject = subjectData.getSubject("?", "PKI", "Ericsson");

        final X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        final X500Name name = builder.build();

        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUP.generateCRMFRequest(name, "dir1");
        final CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);

        final Subject actualSubject = subjectOverrider.overrideSubject(entitySubject, certificateRequest);

        final Subject expectedSubject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION_UNIT, "PKI"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION, "Ericsson"));
        expectedSubject.setSubjectFields(subjectFields);

        assertEquals(expectedSubject, actualSubject);

    }

    /**
     * 
     * entity : CN=?,OU=PKI,O=Ericsson CSR:CN=TestCA,OU=PKICore,O=TCS Output : CN=TestCA,OU=PKI,O=Ericsson
     * 
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws OperatorCreationException
     */

    @Test
    public void testOverrideSubject3_forCRMF() throws NoSuchAlgorithmException, OperatorCreationException, IOException {

        final Subject entitySubject = subjectData.getSubject("?", "PKI", "Ericsson");
        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUP.generateCRMFRequest(new X500Name("CN=TestCA,OU=PKICore,O=TCS"), null);

        final CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);

        final Subject actualSubject = subjectOverrider.overrideSubject(entitySubject, certificateRequest);

        final Subject expectedSubject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.COMMON_NAME, "TestCA"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION_UNIT, "PKI"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION, "Ericsson"));
        expectedSubject.setSubjectFields(subjectFields);

        assertEquals(expectedSubject, actualSubject);

    }

    /**
     * 
     * entity : CN=?,OU=?,O=Ericsson CSR:CN=TestCA,OU=PKICore Output : CN=TestCA,OU=PKICore,O=Ericsson
     * 
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws OperatorCreationException
     */

    @Test
    public void testOverrideSubject4_forCRMF() throws IOException, NoSuchAlgorithmException, OperatorCreationException {

        final Subject entitySubject = subjectData.getSubject("?", "?", "Ericsson");
        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUP.generateCRMFRequest(new X500Name("CN=TestCA,OU=PKICore"), null);

        final CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);

        final Subject actualSubject = subjectOverrider.overrideSubject(entitySubject, certificateRequest);

        final Subject expectedSubject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.COMMON_NAME, "TestCA"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION_UNIT, "PKICore"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION, "Ericsson"));
        expectedSubject.setSubjectFields(subjectFields);

        assertEquals(expectedSubject, actualSubject);

    }

    /**
     * 
     * entity : CN=?,OU=?,O=Ericsson Output : O=Ericsson
     * 
     * @throws IOException
     * @throws OperatorCreationException
     * @throws NoSuchAlgorithmException
     * 
     * 
     */

    @Test
    public void testOverrideSubject5_forCRMF() throws NoSuchAlgorithmException, OperatorCreationException, IOException {

        final Subject entitySubject = subjectData.getSubject("?", "?", "Ericsson");
        final X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        final X500Name name = builder.build();

        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUP.generateCRMFRequest(name, "dir1");

        final CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);

        final Subject actualSubject = subjectOverrider.overrideSubject(entitySubject, certificateRequest);

        final Subject expectedSubject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION, "Ericsson"));
        expectedSubject.setSubjectFields(subjectFields);

        assertEquals(expectedSubject, actualSubject);

    }

    /**
     * 
     * entity : CN=?,OU=?,O=Ericsson CSR: CN=TestCA,OU=PKICore,O=TCS Output : CN=TestCA,OU=Security,O=Ericsson
     * 
     * @throws IOException
     * @throws OperatorCreationException
     * @throws NoSuchAlgorithmException
     * 
     */

    @Test
    public void testOverrideSubject6_forCRMF() throws NoSuchAlgorithmException, OperatorCreationException, IOException {

        final Subject entitySubject = subjectData.getSubject("?", "?", "Ericsson");
        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUP.generateCRMFRequest(new X500Name("CN=TestCA,OU=PKICore,O=TCS"), null);

        final CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);

        final Subject actualSubject = subjectOverrider.overrideSubject(entitySubject, certificateRequest);

        final Subject expectedSubject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.COMMON_NAME, "TestCA"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION_UNIT, "PKICore"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION, "Ericsson"));
        expectedSubject.setSubjectFields(subjectFields);

        assertEquals(expectedSubject, actualSubject);

    }

    /**
     * 
     * entity : CN=?,OU=?,O=? CSR: CN=TestCA,OU=PKICore,O=TCS Output : CN=TestCA,OU=PKICore,O=TCS
     * 
     * @throws OperatorCreationException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */

    @Test
    public void testOverrideSubject7_forCRMF() throws NoSuchAlgorithmException, OperatorCreationException, IOException {

        final Subject entitySubject = subjectData.getSubject("?", "?", "?");

        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUP.generateCRMFRequest(new X500Name("CN=TestCA,OU=PKICore,O=TCS"), null);

        final CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);

        final Subject actualSubject = subjectOverrider.overrideSubject(entitySubject, certificateRequest);

        final Subject expectedSubject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.COMMON_NAME, "TestCA"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION_UNIT, "PKICore"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION, "TCS"));
        expectedSubject.setSubjectFields(subjectFields);

        assertEquals(expectedSubject, actualSubject);

    }

    /**
     * 
     * entity : CN=?,OU=?,O=? Output : empty
     * 
     * @throws IOException
     * @throws OperatorCreationException
     * @throws NoSuchAlgorithmException
     * 
     */
    @Test
    public void testOverrideSubject8_forCRMF() throws IOException, NoSuchAlgorithmException, OperatorCreationException {

        final Subject entitySubject = subjectData.getSubject("?", "?", "?");

        final X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        final X500Name name = builder.build();

        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUP.generateCRMFRequest(name, "dir1");

        final CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
        final CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);

        final Subject subject = subjectOverrider.overrideSubject(entitySubject, certificateRequest);

        assertTrue(subject.getSubjectFields().isEmpty());

    }

    @Test(expected = InvalidSubjectException.class)
    public void testOverride_Subject_UnSupprotedChars1_ThrowsInvalidSubjectException() {

        final Subject entitySubject = subjectData.getSubject(OVERRIDING_OPERATOR, OVERRIDING_OPERATOR, ORGANIZATION);
        CertificateRequestMessage certificateRequestMessage = null;
        try {
            certificateRequestMessage = certificateRequestMessageSetUP.generateCRMFRequest(new X500Name(INVALID_COMMON_NAME), null);
            CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
            final CertificateRequest certificateRequest = new CertificateRequest();
            certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);

            subjectOverrider.overrideSubject(entitySubject, certificateRequest);
        } catch (NoSuchAlgorithmException | OperatorCreationException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    @Test(expected = InvalidSubjectException.class)
    public void testOverride_Subject_UnSupportedChars_Subject_Field_Type_Comma_Not_Supported_ThrowsInvalidSubjectException() {

        final Subject entitySubject = subjectData.getSubject_v1(OVERRIDING_OPERATOR, OVERRIDING_OPERATOR, OVERRIDING_OPERATOR);
        CertificateRequestMessage certificateRequestMessage = null;
        try {
            certificateRequestMessage = certificateRequestMessageSetUP.generateCRMFRequest(new X500Name(INVALID_DC), null);
            CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
            final CertificateRequest certificateRequest = new CertificateRequest();
            certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);

            subjectOverrider.overrideSubject(entitySubject, certificateRequest);
        } catch (NoSuchAlgorithmException | OperatorCreationException | IOException e) {
            e.printStackTrace();
        }

    }

    @Test(expected = InvalidSubjectException.class)
    public void testOverride_Subject_UnSupprotedChars2_ThrowsInvalidSubjectException() {

        final Subject entitySubject = subjectData.getSubject(OVERRIDING_OPERATOR, OVERRIDING_OPERATOR, ORGANIZATION);
        CertificateRequestMessage certificateRequestMessage = null;
        try {
            certificateRequestMessage = certificateRequestMessageSetUP.generateCRMFRequest(new X500Name(INVALID_ORGANIZATION_UNIT), null);
            CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
            final CertificateRequest certificateRequest = new CertificateRequest();
            certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);

            subjectOverrider.overrideSubject(entitySubject, certificateRequest);
        } catch (NoSuchAlgorithmException | OperatorCreationException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    @Test(expected = InvalidSubjectException.class)
    public void testOverride_Subject_UnSupprotedChars3_ThrowsInvalidSubjectException() {

        final Subject entitySubject = subjectData.getSubject(OVERRIDING_OPERATOR, OVERRIDING_OPERATOR, ORGANIZATION);
        CertificateRequestMessage certificateRequestMessage = null;
        try {
            certificateRequestMessage = certificateRequestMessageSetUP.generateCRMFRequest(new X500Name(INVALID_SUBJECT), null);
            CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
            final CertificateRequest certificateRequest = new CertificateRequest();
            certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);

            subjectOverrider.overrideSubject(entitySubject, certificateRequest);
        } catch (NoSuchAlgorithmException | OperatorCreationException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
