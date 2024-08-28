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
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;

@RunWith(MockitoJUnitRunner.class)
public class SubAltNameOverriderTest {

    @InjectMocks
    SubAltNameOverrider subAltNameOverrider;

    @Mock
    Logger logger;

    private static SubjectAltNameSetUPData subjectAltNameData;
    private static PKCS10CertificationRequestSetUPData pKCS10CertificationRequestSetUP;
    private CertificateRequestMessageSetUPData certificateRequestMessageSetUPData;
    private static List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
    private static SubjectAltName entitySubjectAltName;

    // TODO Will be addressed as part of TORF-53891
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void setup() {

        entitySubjectAltName = new SubjectAltName();
        subjectAltNameData = new SubjectAltNameSetUPData();
        pKCS10CertificationRequestSetUP = new PKCS10CertificationRequestSetUPData();
        certificateRequestMessageSetUPData = new CertificateRequestMessageSetUPData();
    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN contains no override operator. entity : DNS=dir1 output : DNS=dir1
     * 
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws IOException
     */
    @Test
    public void testOverrideSubjectAltName1() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName();

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        assertEquals(entitySubjectAltName, actualSubjectAltName);

    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN contains no override operator and no value.
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName2() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName();

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName();

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        assertEquals(entitySubjectAltName, actualSubjectAltName);

    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains one override operator and CSR SAN field DNS contains one value. entity : DNS=? , CSR : DNS=dir7 , output : DNS=dir7
     * 
     * @throws Exception
     * 
     */

    @Test
    public void testOverrideSubjectAltName3() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "?");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir7");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir7");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);

    }

    /**
     * @param csrSubjectAltName
     * @return
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws OperatorCreationException
     */
    private CertificateRequest getCertificateRequest(final SubjectAltName csrSubjectAltName) throws NoSuchAlgorithmException, SignatureException, IOException, InvalidKeyException,
            NoSuchProviderException, OperatorCreationException {

        final CertificateRequest certificateRequest = new CertificateRequest();
        final PKCS10CertificationRequest pkcs10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(subjectAltNameData.getGeneralNameList(csrSubjectAltName
                .getSubjectAltNameFields()));

        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pkcs10CertificationRequest);
        certificateRequest.setCertificateRequestHolder(pkcs10CertificationRequestHolder);

        return certificateRequest;
    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains override operator and CSR SAN contains no field DNS. entity : DNS=? , output : exception
     * 
     * @throws Exception
     */
    @Test
    public void testOverrideSubjectAltName4() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "?");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName();

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        assertTrue(actualSubjectAltName.getSubjectAltNameFields().isEmpty());

    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains one override operator and CSR SAN DNS contains two values. entity : DNS=? , CSR : DNS=dir1,DNS=dir2 , output :
     * DNS=dir1
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName5() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "?");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);

    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains no override operator and CSR SAN DNS contains two values. entity : DNS=dir1,DNS=dir2 , output : DNS=dir1,DNS=dir2
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName6() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName();

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);

    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains one override operator and CSR SAN DNS contains one different value. entity : DNS=dir1,DNS=?,DNS=dir2 , CSR :
     * DNS=dir3 , output=DNS=dir1,DNS=dir2,DNS=dir3
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName7() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "?", "dir2");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir3");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2", "dir3");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);

    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains one override operator and CSR SAN DNS contains no values. entity : DNS=dir1,DNS=?,DNS=dir2 ,
     * output=DNS=dir1,DNS=dir2
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName8() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "?", "dir2");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName();

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);

    }

    /**
     * Method to test overrideSubjectAltName with EDI_PARTY_NAME.
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName_EDI_PARTY_NAME() throws Exception {

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName();

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        mockEDI_PARTY_NAME();

        entitySubjectAltName.setSubjectAltNameFields(subjectAltNameFields);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        assertEquals(true, actualSubjectAltName.isCritical());

        assertEquals(0, actualSubjectAltName.getSubjectAltNameFields().size());

    }

    /**
     * Method to test overrideSubjectAltName with OTHER_NAME.
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName_OTHER_NAME() throws Exception {

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName();

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        mockOTHER_NAME();

        entitySubjectAltName.setSubjectAltNameFields(subjectAltNameFields);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        assertEquals(true, actualSubjectAltName.isCritical());

        assertEquals(0, actualSubjectAltName.getSubjectAltNameFields().size());

    }

    /**
     * Method to test overrideSubjectAltName with IP_ADDRESS.
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName_IP_ADDRESS() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.IP_ADDRESS, "dir1", "?", "dir2");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName();

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.IP_ADDRESS, "dir1", "dir2");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);

    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains one override operator and CSR SAN DNS contains two different values. entity : DNS=dir1,DNS=?,DNS=dir2 , CSR :
     * DNS=dir3,DNS=dir4 , output=DNS=dir1,DNS=dir2,DNS=dir3
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName9() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "?", "dir2");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir3", "dir4");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2", "dir3");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);

    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains one override operator and CSR SAN DNS contains one different value. entity : DNS=dir1,DNS=?,DNS=dir2 , CSR :
     * DNS=dir1,DNS=dir4 , output=DNS=dir1,DNS=dir2,DNS=dir4
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName10() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "?", "dir2");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir4");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2", "dir4");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);

    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains one override operator and CSR SAN DNS contains no different value. entity : DNS=dir1,DNS=?,DNS=dir2 , CSR :
     * DNS=dir1,DNS=dir2 , output=DNS=dir1,DNS=dir2
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName11() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "?", "dir2");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);

    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains three override operators and CSR SAN DNS contains no value. entity : DNS=?,DNS=?,DNS=? , output=exception
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName12() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "?", "?", "?");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName();

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        assertTrue(actualSubjectAltName.getSubjectAltNameFields().isEmpty());

    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains no override operator and CSR SAN DNS contains no value. entity : DNS=dir1,DNS=dir2,DNS=dir3,DNS=dir4 , output :
     * DNS=dir1,DNS=dir2,DNS=dir3,DNS=dir4
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName13() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2", "dir3", "dir4");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName();

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2", "dir3", "dir4");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);
    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains two override operators and CSR SAN DNS contains two different values. entity : DNS=dir1,DNS=?,DNS=dir2,DNS=? , CSR :
     * DNS=dir7,DNS=dir8 output : DNS=dir1,DNS=dir2,DNS=dir7,DNS=dir8
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName14() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "?", "dir2", "?");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir7", "dir8");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2", "dir7", "dir8");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);
    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains two override operators and CSR SAN DNS contains one different value. entity : DNS=dir1,DNS=?,DNS=dir2,DNS=? , CSR :
     * DNS=dir3 , output : DNS=dir1,DNS=dir2,DNS=dir3
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName15() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "?", "dir2", "?");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir3");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2", "dir3");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);
    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains two override operators and CSR SAN DNS contains no values. entity : DNS=dir1,DNS=?,DNS=dir2,DNS=? , output :
     * DNS=dir1,DNS=dir2
     * 
     * @throws Exception
     */
    @Test
    public void testOverrideSubjectAltName16() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "?", "dir2", "?");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName();

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);
    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains two override operators and CSR SAN DNS contains three different values. entity : DNS=dir1,DNS=?,DNS=dir2,DNS=? , CSR
     * : DNS=dir7,DNS=dir8,DNs=9 , output : DNS=dir1,DNS=dir2,DNS=dir7,DNS=dir8
     * 
     * @throws Exception
     */
    @Test
    public void testOverrideSubjectAltName17() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "?", "dir2", "?");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir7", "dir8", "dir9");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2", "dir7", "dir8");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);
    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains two override operators and CSR SAN DNS contains two different values. entity : DNS=dir1,DNS=?,DNS=dir2,DNS=? , CSR :
     * DNS=dir1,DNS=dir8,DNs=9 , output : DNS=dir1,DNS=dir2,DNS=dir8,DNS=dir9
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName18() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "?", "dir2", "?");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir8", "dir9");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2", "dir8", "dir9");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);
    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains two override operators and CSR SAN DNS contains one different value. entity : DNS=dir1,DNS=?,DNS=dir2,DNS=? , CSR :
     * DNS=dir1,DNS=dir8 , output : DNS=dir1,DNS=dir2,DNS=dir8
     * 
     * @throws Exception
     */
    @Test
    public void testOverrideSubjectAltName19() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "?", "dir2", "?");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir8");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2", "dir8");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);
    }

    /**
     * Override entity SAN with CSR SAN for the input entity SAN field DNS contains two override operators and CSR SAN DNS contains one different value. entity : DNS=dir1,DNS=?,DNS=dir2,DNS=? , CSR :
     * DNS=dir1,DNS=dir8 , output : DNS=dir1,DNS=dir2,DNS=dir8
     * 
     * @throws Exception
     */
    @Test
    public void testOverrideSubjectAltName20() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "?", "dir2", "?");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir8");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2", "dir8");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);
    }

    /**
     * Override entity SAN with CSR SAN for the attribute DIRECTORY_NAME
     * 
     * @throws Exception
     */
    @Test
    public void testOverrideSubjectAltName21() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DIRECTORY_NAME, "C=US,CN=Contoso,O=Example", "?", "C=Uk,CN=Contoso,O=Example");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DIRECTORY_NAME, "C=US,CN=Contoso,O=Example", "C=India,CN=Contoso,O=Example");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DIRECTORY_NAME, "C=US,CN=Contoso,O=Example", "C=Uk,CN=Contoso,O=Example",
                "C=India,CN=Contoso,O=Example");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);
    }

    /**
     * Override entity SAN with CSR SAN for the attribute REGESTERED_ID
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName22() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.REGESTERED_ID, "2.5.29.17", "?", "2.5.29.21");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.REGESTERED_ID, "2.5.29.17", "2.5.29.18");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.REGESTERED_ID, "2.5.29.17", "2.5.29.21", "2.5.29.18");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);
    }

    /**
     * Override entity SAN with CSR SAN for the attribute RFC822_NAME
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName23() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.RFC822_NAME, "first@mail.com", "?", "second@mail.com");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.RFC822_NAME, "first@mail.com", "three@mail.com");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.RFC822_NAME, "first@mail.com", "second@mail.com", "three@mail.com");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);
    }

    /**
     * Override entity SAN with CSR SAN for the attribute UNIFORM_RESOURCE_IDENTIFIER
     * 
     * @throws Exception
     */

    @Test
    public void testOverrideSubjectAltName24() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER, "http://www.w3.org/", "?",
                "https://technet.microsoft.com");

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER, "http://www.w3.org/", "https://www.google.com/");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER, "http://www.w3.org/", "https://technet.microsoft.com",
                "https://www.google.com/");
        assertEquals(expectedSubjectAltName, actualSubjectAltName);
    }

    @Test
    public void testOverrideSubjectAltName25() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DIRECTORY_NAME, "?");

        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.DNS_NAME);
        final SubjectAltNameString subjectAltNameString = subjectAltNameData.getSubjectAltNameString("?");
        subjectAltNameField.setValue(subjectAltNameString);

        entitySubjectAltName.getSubjectAltNameFields().add(subjectAltNameField);

        final SubjectAltName csrSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir7");

        final CertificateRequest certificateRequest = getCertificateRequest(csrSubjectAltName);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        final SubjectAltName expectedSubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir7");

        assertEquals(expectedSubjectAltName, actualSubjectAltName);

    }

    @Test
    public void testOverrideSubjectAltName1_forCRMF() throws Exception {

        final SubjectAltName entitySubjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "?");

        final CertificateRequest certificateRequest = new CertificateRequest();
        final X500Name name = new X500Name("CN=RootCA");
        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUPData.generateCRMFRequest(name, "dir1");
        final CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
        certificateRequest.setCertificateRequestHolder(cRMFRequestHolder);

        final SubjectAltName actualSubjectAltName = subAltNameOverrider.overrideSubjectAltName(entitySubjectAltName, certificateRequest);

        assertEquals(entitySubjectAltName, actualSubjectAltName);

    }

    /**
     * Method to set values for EDI_PARTY_NAME.
     * 
     * @throws Exception
     */
    private void mockEDI_PARTY_NAME() {

        entitySubjectAltName.setCritical(true);
        final SubjectAltNameField Sub = new SubjectAltNameField();
        Sub.setType(SubjectAltNameFieldType.EDI_PARTY_NAME);
        final EdiPartyName ediPartyName = new EdiPartyName();
        ediPartyName.setNameAssigner(Constants.OVERRIDE_OPERATOR);
        ediPartyName.setPartyName(Constants.OVERRIDE_OPERATOR);
        Sub.setValue(ediPartyName);
        subjectAltNameFields.add(Sub);
    }

    /**
     * Method to set values for EDI_PARTY_NAME.
     * 
     * @throws Exception
     */
    private void mockOTHER_NAME() {

        entitySubjectAltName.setCritical(true);
        final SubjectAltNameField Sub = new SubjectAltNameField();
        Sub.setType(SubjectAltNameFieldType.OTHER_NAME);
        final OtherName otherName = new OtherName();
        otherName.setTypeId(Constants.OVERRIDE_OPERATOR);
        otherName.setValue(Constants.OVERRIDE_OPERATOR);
        Sub.setValue(otherName);
        subjectAltNameFields.add(Sub);
    }

}