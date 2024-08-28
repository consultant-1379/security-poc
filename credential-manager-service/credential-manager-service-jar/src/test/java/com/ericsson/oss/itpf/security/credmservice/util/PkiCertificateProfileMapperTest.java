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
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiProfileMapperException;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlAccessMethod;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlCertificateVersion;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlKeyPurposeId;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlKeyUsage;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlKeyUsageType;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlReasonFlag;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlSubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.credmservice.profiles.api.ProfileConfigInformation;
import com.ericsson.oss.itpf.security.credmservice.profiles.exceptions.CredentialManagerProfilesException;
import com.ericsson.oss.itpf.security.credmservice.profiles.impl.AppProfileXmlConfiguration;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AccessMethod;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityKeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityKeyIdentifierType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;

public class PkiCertificateProfileMapperTest {

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.credmservice.util.PkiCertificateProfileMapper#ConvertCertificateProfileFrom(com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlCertificateProfile)}
     * .
     */
    @Test
    public void testConvertCertificateProfileFrom1() {

        final File xmlPathTest = new File("src/test/resources/certificateProfile.xml");

        ProfileConfigInformation profileConfigInfo = null;
        try {
            profileConfigInfo = new AppProfileXmlConfiguration(xmlPathTest);

        } catch (final CredentialManagerProfilesException e) {

            e.printStackTrace();
        }

        assertTrue("profileConfigInfo is NULL", profileConfigInfo != null);

        CertificateProfile certificateProfile = null;
        try {
            certificateProfile = PkiCertificateProfileMapper.ConvertCertificateProfileFrom(profileConfigInfo.getCertificateProfilesInfo().get(0));

        } catch (final PkiProfileMapperException e) {

            e.printStackTrace();
        }

        assertTrue("Wrong Certificate Profile Name", certificateProfile.getName().equals("credMCLI_CP"));

    }

    @Test
    public void testConvertCertificateProfileFrom2() {

        final File xmlPathTest = new File("src/test/resources/ENM-PKI-Root-CA_CP.xml");

        ProfileConfigInformation profileConfigInfo = null;
        try {
            profileConfigInfo = new AppProfileXmlConfiguration(xmlPathTest);

        } catch (final CredentialManagerProfilesException e) {

            e.printStackTrace();
        }

        assertTrue("profileConfigInfo is NULL", profileConfigInfo != null);

        CertificateProfile certificateProfile = null;
        try {
            certificateProfile = PkiCertificateProfileMapper.ConvertCertificateProfileFrom(profileConfigInfo.getCertificateProfilesInfo().get(0));

        } catch (final PkiProfileMapperException e) {

            e.printStackTrace();
        }

        assertTrue("Wrong Certificate Profile Name", certificateProfile.getName().equals("ENM PKI Root CA CP"));
        if (certificateProfile.getCertificateExtensions().getCertificateExtensions().get(2) != null)
            System.out.println("Extension 2" + certificateProfile.getCertificateExtensions().getCertificateExtensions().get(2).toString());

        assertTrue("Wrong Certificate Extensions(2)", ((AuthorityKeyIdentifier) (certificateProfile.getCertificateExtensions().getCertificateExtensions().get(2))).getType().equals(AuthorityKeyIdentifierType.SUBJECT_KEY_IDENTIFIER));

    }
    
    @Test
    public void auxiliaryMethodsTest1() {
        
        try {
            Method keyUsageConvert = PkiCertificateProfileMapper.class.getDeclaredMethod("convertKeyUsage", XmlKeyUsageType.class);
            keyUsageConvert.setAccessible(true);
            assertTrue((KeyUsageType) keyUsageConvert.invoke(null, XmlKeyUsageType.KEY_ENCIPHERMENT) == KeyUsageType.KEY_ENCIPHERMENT);
            assertTrue((KeyUsageType) keyUsageConvert.invoke(null, XmlKeyUsageType.DATA_ENCIPHERMENT) == KeyUsageType.DATA_ENCIPHERMENT);
            assertTrue((KeyUsageType) keyUsageConvert.invoke(null, XmlKeyUsageType.KEY_AGREEMENT) == KeyUsageType.KEY_AGREEMENT);
            assertTrue((KeyUsageType) keyUsageConvert.invoke(null, XmlKeyUsageType.ENCIPHER_ONLY) == KeyUsageType.ENCIPHER_ONLY);
            assertTrue((KeyUsageType) keyUsageConvert.invoke(null, XmlKeyUsageType.DECIPHER_ONLY) == KeyUsageType.DECIPHER_ONLY);
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            assertTrue(false);
        }
    }
    @Test
    public void auxiliaryMethodsTest2() {
        try {
            Method keyPurposeConvert = PkiCertificateProfileMapper.class.getDeclaredMethod("convertKeyPurposeId", XmlKeyPurposeId.class);
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
            Method subjAltNameConvert = PkiCertificateProfileMapper.class.getDeclaredMethod("convertSubjectAltName", XmlSubjectAltNameFieldType.class);
            subjAltNameConvert.setAccessible(true);
            assertTrue((SubjectAltNameFieldType) subjAltNameConvert.invoke(null, XmlSubjectAltNameFieldType.RFC_822_NAME) == SubjectAltNameFieldType.RFC822_NAME);
            assertTrue((SubjectAltNameFieldType) subjAltNameConvert.invoke(null, XmlSubjectAltNameFieldType.DNS_NAME) == SubjectAltNameFieldType.DNS_NAME);
            assertTrue((SubjectAltNameFieldType) subjAltNameConvert.invoke(null, XmlSubjectAltNameFieldType.DIRECTORY_NAME) == SubjectAltNameFieldType.DIRECTORY_NAME);
            assertTrue((SubjectAltNameFieldType) subjAltNameConvert.invoke(null, XmlSubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER) == SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER);
            assertTrue((SubjectAltNameFieldType) subjAltNameConvert.invoke(null, XmlSubjectAltNameFieldType.REGESTERED_ID) == SubjectAltNameFieldType.REGESTERED_ID);
        } catch (NoSuchMethodException | IllegalArgumentException | SecurityException | IllegalAccessException | InvocationTargetException e) {
            assertTrue(false);
        }
    }
    
    @Test
    public void auxiliaryMethodsTest4() {
        try {
            Method reasonFlagConvert = PkiCertificateProfileMapper.class.getDeclaredMethod("convertReasonFlag", XmlReasonFlag.class);
            reasonFlagConvert.setAccessible(true);
            assertTrue((ReasonFlag) reasonFlagConvert.invoke(null, XmlReasonFlag.AA_COMPROMISE) == ReasonFlag.AA_COMPROMISE);
            assertTrue((ReasonFlag) reasonFlagConvert.invoke(null, XmlReasonFlag.CA_COMPROMISE) == ReasonFlag.CA_COMPROMISE);
            assertTrue((ReasonFlag) reasonFlagConvert.invoke(null, XmlReasonFlag.AFFILIATION_CHANGED) == ReasonFlag.AFFILIATION_CHANGED);
            assertTrue((ReasonFlag) reasonFlagConvert.invoke(null, XmlReasonFlag.CERTIFICATE_HOLD) == ReasonFlag.CERTIFICATE_HOLD);
            assertTrue((ReasonFlag) reasonFlagConvert.invoke(null, XmlReasonFlag.CESSATION_OF_OPERATION) == ReasonFlag.CESSATION_OF_OPERATION);
            assertTrue((ReasonFlag) reasonFlagConvert.invoke(null, XmlReasonFlag.KEY_COMPROMISE) == ReasonFlag.KEY_COMPROMISE);
            assertTrue((ReasonFlag) reasonFlagConvert.invoke(null, XmlReasonFlag.PRIVILEGE_WITHDRAWN) == ReasonFlag.PRIVILEGE_WITHDRAWN);
            assertTrue((ReasonFlag) reasonFlagConvert.invoke(null, XmlReasonFlag.UNUSED) == ReasonFlag.UNUSED);
        } catch (NoSuchMethodException | IllegalArgumentException | SecurityException | IllegalAccessException | InvocationTargetException e) {
            assertTrue(false);
        }        
    }
    
    @Test
    public void auxiliaryMethodsTest5() {
        try {
            Method accessMethodConvert = PkiCertificateProfileMapper.class.getDeclaredMethod("convertAccessMethod", XmlAccessMethod.class);
            accessMethodConvert.setAccessible(true);
            assertTrue((AccessMethod) accessMethodConvert.invoke(null, XmlAccessMethod.CA_ISSUER) == AccessMethod.CA_ISSUER);
            assertTrue((AccessMethod) accessMethodConvert.invoke(null, XmlAccessMethod.OCSP) == AccessMethod.OCSP);
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            assertTrue(false);
        }
    }

}
