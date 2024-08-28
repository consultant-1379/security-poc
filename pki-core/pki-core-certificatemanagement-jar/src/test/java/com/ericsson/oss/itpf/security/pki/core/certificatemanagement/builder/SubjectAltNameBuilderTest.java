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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificateextension.InvalidSubjectAltNameException;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class SubjectAltNameBuilderTest extends BaseTest {

    @InjectMocks
    SubjectAltNameBuilder subjectAltNameBuilder;

    @Mock
    private CertificateExtension cerificateExtension;

    private SubjectAltName subjectAltName;
    private DEROctetString subjectAltnameExpected;
    private Extension subjectAltNameExtension;
    private CertificateGenerationInfo certificateGenerationInfo;
    private List<GeneralName> generalNameList;

    private static boolean isCritical = true;

    private List<SubjectAltNameField> subjectAltNameFields = null;

    /**
     * Prepares initial data.
     */
    @Before
    public void setup() {

        subjectAltNameFields = new ArrayList<SubjectAltNameField>();
    }

    /**
     * Method to test building of {@link SubjectAltName} extension with DNS names.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testBuildSubjectAltNameForDNSName() throws IOException {

        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("www.ericsson.com");

        prepareSANwithTypeString(SubjectAltNameFieldType.DNS_NAME, subjectAltNameString);

        Mockito.when(certGenInfoParser.getSubjectAltNameFromCertGenerationInfo(certificateGenerationInfo)).thenReturn(subjectAltName);

        subjectAltNameExtension = subjectAltNameBuilder.buildSubjectAltName(subjectAltName, certificateGenerationInfo);

        generalNameList = getSubjectAltNames(subjectAltName.getSubjectAltNameFields());

        subjectAltnameExpected = new DEROctetString(new GeneralNames(generalNameList.toArray(new GeneralName[0])));

        assertExtensionValue(subjectAltnameExpected, subjectAltNameExtension);
        assertEquals(Extension.subjectAlternativeName, subjectAltNameExtension.getExtnId());

        generalNameList.clear();
        subjectAltNameFields.clear();
    }

    /**
     * Method to test building of {@link SubjectAltName} extension with RFC822 names.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testBuildSubjectAltNameForRFC822() throws IOException {

        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("enmSecurity@ericsson.com");

        prepareSANwithTypeString(SubjectAltNameFieldType.RFC822_NAME, subjectAltNameString);

        Mockito.when(certGenInfoParser.getSubjectAltNameFromCertGenerationInfo(certificateGenerationInfo)).thenReturn(subjectAltName);

        subjectAltNameExtension = subjectAltNameBuilder.buildSubjectAltName(subjectAltName, certificateGenerationInfo);

        generalNameList = getSubjectAltNames(subjectAltName.getSubjectAltNameFields());

        subjectAltnameExpected = new DEROctetString(new GeneralNames(generalNameList.toArray(new GeneralName[0])));

        assertExtensionValue(subjectAltnameExpected, subjectAltNameExtension);
        assertEquals(Extension.subjectAlternativeName, subjectAltNameExtension.getExtnId());

        generalNameList.clear();
        subjectAltNameFields.clear();
    }

    /**
     * Method to test building of {@link SubjectAltName} extension with Directory names.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testBuildSubjectAltNameDirectoryName() throws IOException {

        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("CN=ENMSecurity");

        prepareSANwithTypeString(SubjectAltNameFieldType.DIRECTORY_NAME, subjectAltNameString);

        Mockito.when(certGenInfoParser.getSubjectAltNameFromCertGenerationInfo(certificateGenerationInfo)).thenReturn(subjectAltName);

        subjectAltNameExtension = subjectAltNameBuilder.buildSubjectAltName(subjectAltName, certificateGenerationInfo);

        generalNameList = getSubjectAltNames(subjectAltName.getSubjectAltNameFields());

        subjectAltnameExpected = new DEROctetString(new GeneralNames(generalNameList.toArray(new GeneralName[0])));

        assertExtensionValue(subjectAltnameExpected, subjectAltNameExtension);
        assertEquals(Extension.subjectAlternativeName, subjectAltNameExtension.getExtnId());

        generalNameList.clear();
        subjectAltNameFields.clear();
    }

    /**
     * Method to test building of {@link SubjectAltName} extension with IP_ADDRESS field.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testBuildSubjectAltNameWithIPV4Adress() throws IOException {

        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("127.0.0.1");

        prepareSANwithTypeString(SubjectAltNameFieldType.IP_ADDRESS, subjectAltNameString);

        Mockito.when(certGenInfoParser.getSubjectAltNameFromCertGenerationInfo(certificateGenerationInfo)).thenReturn(subjectAltName);

        subjectAltNameExtension = subjectAltNameBuilder.buildSubjectAltName(subjectAltName, certificateGenerationInfo);

        generalNameList = getSubjectAltNames(subjectAltName.getSubjectAltNameFields());

        subjectAltnameExpected = new DEROctetString(new GeneralNames(generalNameList.toArray(new GeneralName[0])));

        assertExtensionValue(subjectAltnameExpected, subjectAltNameExtension);
        assertEquals(Extension.subjectAlternativeName, subjectAltNameExtension.getExtnId());

        generalNameList.clear();
        subjectAltNameFields.clear();
    }

    /**
     * Method to test building of {@link SubjectAltName} extension with IP_ADDRESS field.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testBuildSubjectAltNameWithIPV6Adress() throws IOException {

        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("2001:0db8:85a3:0000:0000:8a2e:0370:7334");

        prepareSANwithTypeString(SubjectAltNameFieldType.IP_ADDRESS, subjectAltNameString);

        Mockito.when(certGenInfoParser.getSubjectAltNameFromCertGenerationInfo(certificateGenerationInfo)).thenReturn(subjectAltName);

        subjectAltNameExtension = subjectAltNameBuilder.buildSubjectAltName(subjectAltName, certificateGenerationInfo);

        generalNameList = getSubjectAltNames(subjectAltName.getSubjectAltNameFields());

        subjectAltnameExpected = new DEROctetString(new GeneralNames(generalNameList.toArray(new GeneralName[0])));

        assertExtensionValue(subjectAltnameExpected, subjectAltNameExtension);
        assertEquals(Extension.subjectAlternativeName, subjectAltNameExtension.getExtnId());

        generalNameList.clear();
        subjectAltNameFields.clear();
    }

    /**
     * Method to test building of {@link SubjectAltName} extension with IP_ADDRESS field.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test(expected = NullPointerException.class)
    public void testBuildSubjectAltNameWithIPAdress_WithInvalidInput() throws IOException {
        prepareSANwithIPAddress_WithInvalidInput();

        Mockito.when(certGenInfoParser.getSubjectAltNameFromCertGenerationInfo(certificateGenerationInfo)).thenReturn(subjectAltName);

        subjectAltNameBuilder.buildSubjectAltName(subjectAltName, certificateGenerationInfo);

        generalNameList.clear();
        subjectAltNameFields.clear();
    }

    /**
     * Method to test building of {@link SubjectAltName} extension with URI field.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testBuildSubjectAltNameWithURI() throws IOException {

        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("http://www.subjectAltName.com");

        prepareSANwithTypeString(SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER, subjectAltNameString);

        Mockito.when(certGenInfoParser.getSubjectAltNameFromCertGenerationInfo(certificateGenerationInfo)).thenReturn(subjectAltName);

        subjectAltNameExtension = subjectAltNameBuilder.buildSubjectAltName(subjectAltName, certificateGenerationInfo);

        generalNameList = getSubjectAltNames(subjectAltName.getSubjectAltNameFields());

        subjectAltnameExpected = new DEROctetString(new GeneralNames(generalNameList.toArray(new GeneralName[0])));

        assertExtensionValue(subjectAltnameExpected, subjectAltNameExtension);
        assertEquals(Extension.subjectAlternativeName, subjectAltNameExtension.getExtnId());

        generalNameList.clear();
        subjectAltNameFields.clear();
    }

    /**
     * Method to test building of {@link SubjectAltName} extension with OtherName field.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testBuildSubjectAltNameWithOtherName() throws IOException {

        prepareSANwithOtherName();

        Mockito.when(certGenInfoParser.getSubjectAltNameFromCertGenerationInfo(certificateGenerationInfo)).thenReturn(subjectAltName);

        subjectAltNameExtension = subjectAltNameBuilder.buildSubjectAltName(subjectAltName, certificateGenerationInfo);

        generalNameList = getSubjectAltNames(subjectAltName.getSubjectAltNameFields());

        subjectAltnameExpected = new DEROctetString(new GeneralNames(generalNameList.toArray(new GeneralName[0])));

        assertExtensionValue(subjectAltnameExpected, subjectAltNameExtension);
        assertEquals(Extension.subjectAlternativeName, subjectAltNameExtension.getExtnId());

        generalNameList.clear();
        subjectAltNameFields.clear();
    }

    /**
     * Method to test building of {@link SubjectAltName} extension with EDIPartyName field.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testBuildSubjectAltNameWithEDIPartyName() throws IOException {

        prepareSANwithEDIPartyName();

        Mockito.when(certGenInfoParser.getSubjectAltNameFromCertGenerationInfo(certificateGenerationInfo)).thenReturn(subjectAltName);

        subjectAltNameExtension = subjectAltNameBuilder.buildSubjectAltName(subjectAltName, certificateGenerationInfo);

        generalNameList = getSubjectAltNames(subjectAltName.getSubjectAltNameFields());

        subjectAltnameExpected = new DEROctetString(new GeneralNames(generalNameList.toArray(new GeneralName[0])));

        assertExtensionValue(subjectAltnameExpected, subjectAltNameExtension);
        assertEquals(Extension.subjectAlternativeName, subjectAltNameExtension.getExtnId());

        generalNameList.clear();
        subjectAltNameFields.clear();
    }

    private int getSANFieldType(final SubjectAltNameFieldType type) {
        switch (type) {
        case RFC822_NAME:
            return GeneralName.rfc822Name;
        case DNS_NAME:
            return GeneralName.dNSName;
        case DIRECTORY_NAME:
            return GeneralName.directoryName;
        case IP_ADDRESS:
            return GeneralName.iPAddress;
        case REGESTERED_ID:
            return GeneralName.registeredID;
        case UNIFORM_RESOURCE_IDENTIFIER:
            return GeneralName.uniformResourceIdentifier;
        case EDI_PARTY_NAME:
            return GeneralName.ediPartyName;
        case OTHER_NAME:
            return GeneralName.otherName;
        default:
            throw new IllegalArgumentException(ErrorMessages.INVALID_SANFIELD_TYPE);
        }
    }

    private List<GeneralName> getSubjectAltNames(final List<SubjectAltNameField> subjectAltNameFields) {

        final List<GeneralName> generalNameList = new ArrayList<GeneralName>();

        for (final SubjectAltNameField subjectAltNameField : subjectAltNameFields) {
            addSANValue(generalNameList, subjectAltNameField);
        }
        logger.debug("List of GeneralNames added for SubjectAltName {} ", generalNameList);

        return generalNameList;
    }

    private void addSANValue(final List<GeneralName> generalNameList, final SubjectAltNameField subjectAltNameField) {

        final SubjectAltNameFieldType sANFieldType = subjectAltNameField.getType();

        final AbstractSubjectAltNameFieldValue sANValue = subjectAltNameField.getValue();
        final GeneralName generalName = new GeneralName(getSANFieldType(sANFieldType), getSANFieldValue(subjectAltNameField.getType(), sANValue));
        generalNameList.add(generalName);
    }

    private ASN1Encodable getSANFieldValue(final SubjectAltNameFieldType type, final AbstractSubjectAltNameFieldValue abstractSubjectAltNameFieldValue) throws InvalidSubjectAltNameException {

        switch (type) {
        case RFC822_NAME:
        case DNS_NAME:
        case EDI_PARTY_NAME:
        case UNIFORM_RESOURCE_IDENTIFIER:
            return new DERIA5String(abstractSubjectAltNameFieldValue.toString());
        case DIRECTORY_NAME:
            return new X500Name(abstractSubjectAltNameFieldValue.toString());
        case IP_ADDRESS:
            return new DEROctetString(ipStringToOctets(abstractSubjectAltNameFieldValue.toString()));
        case REGESTERED_ID:
            return ASN1ObjectIdentifier.getInstance(abstractSubjectAltNameFieldValue.toString());
        case OTHER_NAME:
            return new DERUTF8String(abstractSubjectAltNameFieldValue.toString());
        default:
            throw new InvalidSubjectAltNameException(ErrorMessages.INVALID_SANFIELD_TYPE);
        }
    }

    private static byte[] ipStringToOctets(final String str) {
        final String[] toks = str.split("[.:]");
        if (toks.length == 4) {
            // IPv4 address such as 192.168.5.45
            final byte[] ret = new byte[4];
            for (int i = 0; i < toks.length; i++) {
                final int t = Integer.parseInt(toks[i]);
                if (t > 255) {
                    return null;
                }
                ret[i] = (byte) t;
            }
            return ret;
        }
        if (toks.length == 8) {
            // IPv6 address such as 2001:0db8:85a3:0000:0000:8a2e:0370:7334
            final byte[] ret = new byte[16];
            int ind = 0;
            for (int i = 0; i < toks.length; i++) {
                final int t = Integer.parseInt(toks[i], 16);
                if (t > 0xFFFF) {
                    return null;
                }
                final int t1 = t >> 8;
                final int b1 = t1 & 0x00FF;
                // int b1 = t & 0x00FF;
                ret[ind++] = (byte) b1;
                // int b2 = t & 0xFF00;
                final int b2 = t & 0x00FF;
                ret[ind++] = (byte) b2;
            }
            return ret;
        }
        return new byte[0];
    }

    private void prepareSANwithTypeString(final SubjectAltNameFieldType subjectAltNameFieldType, final SubjectAltNameString subjectAltNameString) {

        subjectAltName = new SubjectAltName();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(subjectAltNameFieldType);
        subjectAltNameField.setValue(subjectAltNameString);

        subjectAltNameFields.add(subjectAltNameField);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);
        subjectAltName.setCritical(isCritical);
    }

    private void prepareSANwithIPAddress_WithInvalidInput() {

        subjectAltName = new SubjectAltName();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();

        final SubjectAltNameString ipAddress = new SubjectAltNameString();
        ipAddress.setValue("256.255.255.255");

        subjectAltNameField.setType(SubjectAltNameFieldType.IP_ADDRESS);
        subjectAltNameField.setValue(ipAddress);
        subjectAltNameFields.add(subjectAltNameField);

        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);
    }

    private void prepareSANwithOtherName() {

        subjectAltName = new SubjectAltName();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();

        final OtherName otherName = new OtherName();
        otherName.setTypeId("1.2.3.4.5");
        otherName.setValue("Test value");

        subjectAltNameField.setType(SubjectAltNameFieldType.OTHER_NAME);
        subjectAltNameField.setValue(otherName);

        subjectAltNameFields.add(subjectAltNameField);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);
        subjectAltName.setCritical(isCritical);
    }

    private void prepareSANwithEDIPartyName() {

        subjectAltName = new SubjectAltName();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();

        final EdiPartyName ediPartyName = new EdiPartyName();
        ediPartyName.setNameAssigner("Ericsson");
        ediPartyName.setPartyName("Security");

        subjectAltNameField.setType(SubjectAltNameFieldType.EDI_PARTY_NAME);
        subjectAltNameField.setValue(ediPartyName);

        subjectAltNameFields.add(subjectAltNameField);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);
        subjectAltName.setCritical(isCritical);
    }
}
