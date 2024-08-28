package com.ericsson.oss.itpf.security.pki.ra.scep.data;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.ra.scep.data.IssuerAndSubjectName;

@RunWith(MockitoJUnitRunner.class)
public class IssuerAndSubjectNameTest {

    @InjectMocks
    IssuerAndSubjectName issuerAndSubjectName;

    private X500Name subjectName;
    private X500Name issuerName;
    private byte[] issuerAndSubject;
    private IssuerAndSubjectName issuerAndSubjectNameData;

    @Before
    public void setUp() throws Exception {

        subjectName = new X500Name("CN=" + "atclvm1022:lienb0511_cus_ipsec");
        issuerName = new X500Name("O=Ericsson,CN=LTEIPSecNEcusRootCA");

        issuerAndSubjectName = new IssuerAndSubjectName();
        issuerAndSubjectNameData = new IssuerAndSubjectName(issuerName, subjectName);

        issuerAndSubject = issuerAndSubjectNameData.getEncoded();

    }

    @Test
    public void testGetInstance_encodedIssuerAndSubject_objectIssuerAndSubjectName() throws IOException {

        IssuerAndSubjectName issuerAndSubjectNameReturn = IssuerAndSubjectName.getInstance(issuerAndSubject);

        assertNotNull(issuerAndSubjectNameReturn);
        assertEquals(issuerAndSubjectNameData.getIssuerName().hashCode(), issuerAndSubjectNameReturn.getIssuerName().hashCode());
        assertEquals(issuerAndSubjectNameData.getSubjectName().hashCode(), issuerAndSubjectNameReturn.getSubjectName().hashCode());
    }

    @Test
    public void testIssuerName_setIssuerName_getIssuerName() {

        issuerAndSubjectName.setIssuerName(issuerName);

        X500Name issuerNameReturn = issuerAndSubjectName.getIssuerName();

        assertNotNull(issuerNameReturn);
        assertEquals(issuerName.hashCode(), issuerNameReturn.hashCode());

    }

    @Test
    public void testSubjectName_setSubjectName_getSubjectName() {

        issuerAndSubjectName.setSubjectName(subjectName);

        X500Name subjectNameReturn = issuerAndSubjectName.getSubjectName();

        assertNotNull(subjectNameReturn);
        assertEquals(subjectName.hashCode(), subjectNameReturn.hashCode());
    }

    @Test
    public void testToASN1Primitive_issuerAndSubjectName_ASN1Primitive() {

        ASN1Primitive aSN1Primitive = issuerAndSubjectNameData.toASN1Primitive();

        assertNotNull(aSN1Primitive);

    }

}
