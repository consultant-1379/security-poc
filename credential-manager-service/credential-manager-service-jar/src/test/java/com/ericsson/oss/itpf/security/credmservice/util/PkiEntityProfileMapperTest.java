/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.util;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiProfileMapperException;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlKeyPurposeId;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlKeyUsageType;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlSubjectFieldType;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlAccessMethod;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlReasonFlag;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlSubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.credmservice.profiles.api.ProfileConfigInformation;
import com.ericsson.oss.itpf.security.credmservice.profiles.exceptions.CredentialManagerProfilesException;
import com.ericsson.oss.itpf.security.credmservice.profiles.impl.AppProfileXmlConfiguration;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AccessMethod;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.OtherName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

public class PkiEntityProfileMapperTest {

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.credmservice.util.PkiEntityProfileMapper#ConvertEntityProfileFrom(com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlEntityProfile)} .
     */
    @Test
    public void testConvertEntityProfileFrom1() {

        final File xmlPathTest = new File("src/test/resources/endEntityProfile.xml");

        ProfileConfigInformation profileConfigInfo = null;
        try {
            profileConfigInfo = new AppProfileXmlConfiguration(xmlPathTest);

        } catch (final CredentialManagerProfilesException e) {

            e.printStackTrace();
        }

        assertTrue("profileConfigInfo is NULL", profileConfigInfo != null);

        EntityProfile entityProfile = null;
        try {
            entityProfile = PkiEntityProfileMapper.ConvertEntityProfileFrom(profileConfigInfo.getEntityProfilesInfo().get(0));

        } catch (PkiProfileMapperException e) {

            e.printStackTrace();
        }

        assertTrue("Wrong EntityProfileName", entityProfile.getName().equals("credMCLI_EP"));

        assertTrue("Wrong SubjectAltNameFieldValue", ((OtherName) (entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields().get(0).getValue())).getValue().equals("value"));

        assertTrue("Wrong SubjectAltNameFieldTypeId", ((OtherName) (entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields().get(0).getValue())).getTypeId().equals("1.6.5.1.8"));

    }

    @Test
    public void testConvertEntityProfileFrom2() {

        final File xmlPathTest = new File("src/test/resources/ENM-Sub2-CA_EP.xml");

        ProfileConfigInformation profileConfigInfo = null;
        try {
            profileConfigInfo = new AppProfileXmlConfiguration(xmlPathTest);

        } catch (final CredentialManagerProfilesException e) {

            e.printStackTrace();
        }

        assertTrue("profileConfigInfo is NULL", profileConfigInfo != null);

        EntityProfile entityProfile = null;
        try {
            entityProfile = PkiEntityProfileMapper.ConvertEntityProfileFrom(profileConfigInfo.getEntityProfilesInfo().get(0));

        } catch (PkiProfileMapperException e) {

            e.printStackTrace();
        }

        assertTrue("Wrong EntityName", entityProfile.getName().equals("ENM System CA EP"));

        assertTrue("Wrong CertificateProfileName", entityProfile.getCertificateProfile().getName().equals("ENM System CA CP"));
    }
    
    @Test
    public void testEntityProfile3() throws NoSuchMethodException, SecurityException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        
        Constructor<PkiEntityProfileMapper> privConstr = PkiEntityProfileMapper.class.getDeclaredConstructor();
        privConstr.setAccessible(true);
        PkiEntityProfileMapper pkiEPM = privConstr.newInstance();
        assertTrue(pkiEPM != null);
        try {
            PkiEntityProfileMapper.ConvertEntityProfileFrom(null);
            assertTrue(false);
        } catch (PkiProfileMapperException e) {
            assertTrue(true);
        }
        
    }
    
    @Test
    public void auxiliaryMethodsTest1() {
        
        try {
            Method keyUsageConvert = PkiEntityProfileMapper.class.getDeclaredMethod("convertKeyUsage", XmlKeyUsageType.class);
            keyUsageConvert.setAccessible(true);
            assertTrue((KeyUsageType) keyUsageConvert.invoke(null, XmlKeyUsageType.KEY_ENCIPHERMENT) == KeyUsageType.KEY_ENCIPHERMENT);
            assertTrue((KeyUsageType) keyUsageConvert.invoke(null, XmlKeyUsageType.DATA_ENCIPHERMENT) == KeyUsageType.DATA_ENCIPHERMENT);
            assertTrue((KeyUsageType) keyUsageConvert.invoke(null, XmlKeyUsageType.KEY_AGREEMENT) == KeyUsageType.KEY_AGREEMENT);
            assertTrue((KeyUsageType) keyUsageConvert.invoke(null, XmlKeyUsageType.ENCIPHER_ONLY) == KeyUsageType.ENCIPHER_ONLY);
            assertTrue((KeyUsageType) keyUsageConvert.invoke(null, XmlKeyUsageType.DECIPHER_ONLY) == KeyUsageType.DECIPHER_ONLY);
            assertTrue((KeyUsageType) keyUsageConvert.invoke(null, XmlKeyUsageType.DIGITAL_SIGNATURE) == KeyUsageType.DIGITAL_SIGNATURE);
            assertTrue((KeyUsageType) keyUsageConvert.invoke(null, XmlKeyUsageType.KEY_CERT_SIGN) == KeyUsageType.KEY_CERT_SIGN);
            assertTrue((KeyUsageType) keyUsageConvert.invoke(null, XmlKeyUsageType.CRL_SIGN) == KeyUsageType.CRL_SIGN);
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            assertTrue(false);
        }
    }
    @Test
    public void auxiliaryMethodsTest2() {
        try {
            Method keyPurposeConvert = PkiEntityProfileMapper.class.getDeclaredMethod("convertKeyPurposeId", XmlKeyPurposeId.class);
            keyPurposeConvert.setAccessible(true);
            assertTrue((KeyPurposeId) keyPurposeConvert.invoke(null, XmlKeyPurposeId.ANY_EXTENDED_KEY_USAGE) == KeyPurposeId.ANY_EXTENDED_KEY_USAGE);
            assertTrue((KeyPurposeId) keyPurposeConvert.invoke(null, XmlKeyPurposeId.ID_KP_CODE_SIGNING) == KeyPurposeId.ID_KP_CODE_SIGNING);
            assertTrue((KeyPurposeId) keyPurposeConvert.invoke(null, XmlKeyPurposeId.ID_KP_EMAIL_PROTECTION) == KeyPurposeId.ID_KP_EMAIL_PROTECTION);
            assertTrue((KeyPurposeId) keyPurposeConvert.invoke(null, XmlKeyPurposeId.ID_KP_TIMESTAMPING) == KeyPurposeId.ID_KP_TIME_STAMPING);
            assertTrue((KeyPurposeId) keyPurposeConvert.invoke(null, XmlKeyPurposeId.ID_KP_OCSP_SIGNING) == KeyPurposeId.ID_KP_OCSP_SIGNING);
            assertTrue((KeyPurposeId) keyPurposeConvert.invoke(null, XmlKeyPurposeId.ID_KP_SERVER_AUTH) == KeyPurposeId.ID_KP_SERVER_AUTH);
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            assertTrue(false);
        }
    }
    
    @Test
    public void auxiliaryMethodsTest3() {
        try {            
            Method subjAltNameConvert = PkiEntityProfileMapper.class.getDeclaredMethod("convertSubjectAltName", XmlSubjectAltNameFieldType.class);
            subjAltNameConvert.setAccessible(true);
            assertTrue((SubjectAltNameFieldType) subjAltNameConvert.invoke(null, XmlSubjectAltNameFieldType.RFC_822_NAME) == SubjectAltNameFieldType.RFC822_NAME);
            assertTrue((SubjectAltNameFieldType) subjAltNameConvert.invoke(null, XmlSubjectAltNameFieldType.DNS_NAME) == SubjectAltNameFieldType.DNS_NAME);
            assertTrue((SubjectAltNameFieldType) subjAltNameConvert.invoke(null, XmlSubjectAltNameFieldType.DIRECTORY_NAME) == SubjectAltNameFieldType.DIRECTORY_NAME);
            assertTrue((SubjectAltNameFieldType) subjAltNameConvert.invoke(null, XmlSubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER) == SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER);
            assertTrue((SubjectAltNameFieldType) subjAltNameConvert.invoke(null, XmlSubjectAltNameFieldType.REGESTERED_ID) == SubjectAltNameFieldType.REGESTERED_ID);
            assertTrue((SubjectAltNameFieldType) subjAltNameConvert.invoke(null, XmlSubjectAltNameFieldType.IP_ADDRESS) == SubjectAltNameFieldType.IP_ADDRESS);
        } catch (NoSuchMethodException | IllegalArgumentException | SecurityException | IllegalAccessException | InvocationTargetException e) {
            assertTrue(false);
        }
    }
    
    @Test
    public void auxiliaryMethodsTest4() {
        try {
            Method reasonFlagConvert = PkiEntityProfileMapper.class.getDeclaredMethod("convertReasonFlag", XmlReasonFlag.class);
            reasonFlagConvert.setAccessible(true);
            assertTrue((ReasonFlag) reasonFlagConvert.invoke(null, XmlReasonFlag.AA_COMPROMISE) == ReasonFlag.AA_COMPROMISE);
            assertTrue((ReasonFlag) reasonFlagConvert.invoke(null, XmlReasonFlag.CA_COMPROMISE) == ReasonFlag.CA_COMPROMISE);
            assertTrue((ReasonFlag) reasonFlagConvert.invoke(null, XmlReasonFlag.AFFILIATION_CHANGED) == ReasonFlag.AFFILIATION_CHANGED);
            assertTrue((ReasonFlag) reasonFlagConvert.invoke(null, XmlReasonFlag.CERTIFICATE_HOLD) == ReasonFlag.CERTIFICATE_HOLD);
            assertTrue((ReasonFlag) reasonFlagConvert.invoke(null, XmlReasonFlag.CESSATION_OF_OPERATION) == ReasonFlag.CESSATION_OF_OPERATION);
            assertTrue((ReasonFlag) reasonFlagConvert.invoke(null, XmlReasonFlag.KEY_COMPROMISE) == ReasonFlag.KEY_COMPROMISE);
            assertTrue((ReasonFlag) reasonFlagConvert.invoke(null, XmlReasonFlag.PRIVILEGE_WITHDRAWN) == ReasonFlag.PRIVILEGE_WITHDRAWN);
            assertTrue((ReasonFlag) reasonFlagConvert.invoke(null, XmlReasonFlag.UNUSED) == ReasonFlag.UNUSED);
        } catch (NoSuchMethodException |IllegalArgumentException | SecurityException | IllegalAccessException | InvocationTargetException e) {
            assertTrue(false);
        }
        
    }
    
    @Test
    public void auxiliaryMethodsTest5() {
        try {
            Method subjectFieldConvert = PkiEntityProfileMapper.class.getDeclaredMethod("convertSubjectFieldType", XmlSubjectFieldType.class);
            subjectFieldConvert.setAccessible(true);
            assertTrue((SubjectFieldType) subjectFieldConvert.invoke(null, XmlSubjectFieldType.SURNAME) == SubjectFieldType.SURNAME);
            assertTrue((SubjectFieldType) subjectFieldConvert.invoke(null, XmlSubjectFieldType.LOCALITY_NAME) == SubjectFieldType.LOCALITY_NAME);
            assertTrue((SubjectFieldType) subjectFieldConvert.invoke(null, XmlSubjectFieldType.STATE) == SubjectFieldType.STATE);
            assertTrue((SubjectFieldType) subjectFieldConvert.invoke(null, XmlSubjectFieldType.STREET_ADDRESS) == SubjectFieldType.STREET_ADDRESS);
            assertTrue((SubjectFieldType) subjectFieldConvert.invoke(null, XmlSubjectFieldType.DN_QUALIFIER) == SubjectFieldType.DN_QUALIFIER);
            assertTrue((SubjectFieldType) subjectFieldConvert.invoke(null, XmlSubjectFieldType.TITLE) == SubjectFieldType.TITLE);
            assertTrue((SubjectFieldType) subjectFieldConvert.invoke(null, XmlSubjectFieldType.GIVEN_NAME) == SubjectFieldType.GIVEN_NAME);
            assertTrue((SubjectFieldType) subjectFieldConvert.invoke(null, XmlSubjectFieldType.SERIAL_NUMBER) == SubjectFieldType.SERIAL_NUMBER);
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            assertTrue(false);
        }
    }

    @Test
    public void auxiliaryMethodsTest6() {
        try {
            Method accessMethodConvert = PkiEntityProfileMapper.class.getDeclaredMethod("convertAccessMethod", XmlAccessMethod.class);
            accessMethodConvert.setAccessible(true);
            assertTrue((AccessMethod) accessMethodConvert.invoke(null, XmlAccessMethod.CA_ISSUER) == AccessMethod.CA_ISSUER);
            assertTrue((AccessMethod) accessMethodConvert.invoke(null, XmlAccessMethod.OCSP) == AccessMethod.OCSP);
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            assertTrue(false);
        }
    }
    
}
