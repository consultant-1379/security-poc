package com.ericsson.oss.iptf.security.credmsapi.test;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x509.Attribute;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateExtensionType;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtension;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtensionImpl;
import com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.CSRAttributesHandler;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerBasicConstraints;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateExtensions;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerExtendedKeyUsage;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerKeyPurposeId;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerKeyUsage;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerKeyUsageType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectKeyIdentifier;

@RunWith(JUnit4.class)
public class CsrAttributesUnitTest {

    CSRAttributesHandler csrAttHandler = new CSRAttributesHandler();
    private static final Logger LOG = LogManager.getLogger(CsrAttributesUnitTest.class);

    @Test
    public void testGenerateAttributes() {

        /*
         * generate a profile with all possible extensions (SubjectAltName, keyUsage, ExtendedKeyUsage, SubjectKeyIdentifier)
         */
        testGenerateAttributesWithExtensionParams(true, true, true);

        /*
         * generate a profile with SubjectAltName, keyUsage, ExtendedKeyUsage and NOT SubjectKeyIdentifier
         */
        testGenerateAttributesWithExtensionParams(true, true, false);

        /*
         * generate a profile with SubjectAltName, keyUsage, SubjectKeyIdentifier and NOT ExtendedKeyUsage
         */
        testGenerateAttributesWithExtensionParams(true, false, true);

        /*
         * generate a profile with SubjectAltName, keyUsage and NOT ExtendedKeyUsage and NOT SubjectKeyIdentifier
         */
        testGenerateAttributesWithExtensionParams(true, false, false);

        /*
         * generate a profile with SubjectAltName, Extended key Usage, SubjectKeyIdentifier and NOT KeyUsage
         */
        testGenerateAttributesWithExtensionParams(false, true, true);

        /*
         * generate a profile with SubjectAltName, Extended key Usage and NOT KeyUsage and NOT SubjectKeyIdentifier
         */
        testGenerateAttributesWithExtensionParams(false, true, false);

        /*
         * generate a profile with only SubjectAlternateName and SubjectKeyIdentifier
         */
        testGenerateAttributesWithExtensionParams(false, false, true);

        /*
         * generate a profile with only SubjectAlternateName
         */
        testGenerateAttributesWithExtensionParams(false, false, false);

    }

    public void testGenerateAttributesWithExtensionParams(final Boolean fillKeyUsage, final Boolean fillExtendedKeyUsage, final Boolean fillSubjectKeyIdentifier) {

        final CredentialManagerCertificateExtension extentionFromXml = prepareParametersXML();
        final CredentialManagerProfileInfo profileInfo = prepareParametersProfile(fillKeyUsage, fillExtendedKeyUsage, fillSubjectKeyIdentifier);

        /*
         * Invoke generateDERAttributes method of CSRAttributesHandler class
         */
        Attribute[] attributesXml;
        Attribute[] attributesProfile;

        /**
         * The first call with both parameters not null should return attributes from XML
         */
        attributesXml = csrAttHandler.generateAttributes(profileInfo, extentionFromXml);

        assertTrue("attributes from XML is not null", attributesXml != null);

        /**
         * The second call with XML parameters null should return attributes from Profile
         */
        final CertificateExtensionType certExtType = new CertificateExtensionType();
        certExtType.setSubjectalternativename(new SubjectAlternativeNameType());
        final CredentialManagerCertificateExtension extentionFromXmlDummy = new CredentialManagerCertificateExtensionImpl(certExtType);

        attributesProfile = csrAttHandler.generateAttributes(profileInfo, extentionFromXmlDummy);
        // profileInfo, null);

        assertTrue("attributes from Profile is not null", attributesProfile != null);


    }

    private CredentialManagerCertificateExtension prepareParametersXML() {

        /*
         * Prepare parameters to invoke getCsr method of CsrHandler class
         */
        final SubjectAlternativeNameType subjectAltNameXml = new SubjectAlternativeNameType();

        /**
         * Insert Field with values
         */

        final List<String> directoryName = new ArrayList<String>();
        directoryName.add("DN=HOST_NAME");
        subjectAltNameXml.setDirectoryname(directoryName);

        final List<String> dns = new ArrayList<String>();
        dns.add("dns");
        subjectAltNameXml.setDns(dns);

        // List<String> email = new ArrayList<String>();
        // email.add("NAME@ericsson.com");
        // subjectAltNameXml.setEmail(email);

        final List<String> ipaddress = new ArrayList<String>();
        ipaddress.add("1.1.1.1");
        subjectAltNameXml.setIpaddress(ipaddress);

        // List<String> othername = new ArrayList<String>();
        // othername.add("othername");
        // subjectAltNameXml.setOthername(othername);

        // List<String> registerid = new ArrayList<String>();
        // registerid.add("registerid");
        // subjectAltNameXml.setRegisteredid(registerid);

        final List<String> uri = new ArrayList<String>();
        uri.add("uri");
        subjectAltNameXml.setUri(uri);

        final CertificateExtensionType certExtType = new CertificateExtensionType();
        certExtType.setSubjectalternativename(subjectAltNameXml);

        final CredentialManagerCertificateExtension certificationExtentionFromXml = new CredentialManagerCertificateExtensionImpl(certExtType);

        return certificationExtentionFromXml;

    }

    private CredentialManagerProfileInfo prepareParametersProfile(final Boolean fillKeyusage, final Boolean fillExtendedKeyUsage, final Boolean fillSubjectKeyIdentifier) {

        /*
         * Prepare parameters to invoke getCsr method of CsrHandler class
         */
        final CredentialManagerProfileInfo profileInfo = new CredentialManagerProfileInfo();

        final CredentialManagerSubjectAltName subjectDefaultAlternativeName = new CredentialManagerSubjectAltName();

        /**
         * Insert Field with values
         */

        final List<String> directoryName = new ArrayList<String>();
        directoryName.add("DN=HOST_NAME");
        subjectDefaultAlternativeName.setDirectoryName(directoryName);

        final List<String> dns = new ArrayList<String>();
        dns.add("dns");
        subjectDefaultAlternativeName.setDNSName(dns);

        // List<String> email = new ArrayList<String>();
        // email.add("NAME@ericsson.com");
        // subjectDefaultAlternativeName.setX400Address(email);

        final List<String> ipaddress = new ArrayList<String>();
        ipaddress.add("1.1.1.1");
        subjectDefaultAlternativeName.setIPAddress(ipaddress);

        // List<CredentialManagerOtherName> othername = new
        // ArrayList<CredentialManagerOtherName>();
        // CredentialManagerOtherName element = new
        // CredentialManagerOtherName();
        // element.setValue("othername");
        // element.setTypeId("");
        // othername.add(element);
        // subjectDefaultAlternativeName.setOtherName(othername);

        // List<String> registerid = new ArrayList<String>();
        // registerid.add("registerid");
        // subjectDefaultAlternativeName.setRegisteredID(registerid);

        final List<String> uri = new ArrayList<String>();
        uri.add("uri");
        subjectDefaultAlternativeName.setUniformResourceIdentifier(uri);

        profileInfo.setSubjectDefaultAlternativeName(subjectDefaultAlternativeName);

        if (fillKeyusage == true || fillExtendedKeyUsage == true || fillSubjectKeyIdentifier == true) {

            final CredentialManagerCertificateExtensions credentialManagerCertificateExtensions = new CredentialManagerCertificateExtensions();

            /**
             * prepare Basic Constraints
             */
            final CredentialManagerBasicConstraints basicConstraints = new CredentialManagerBasicConstraints();

            basicConstraints.setCritical(true);
            basicConstraints.setCA(false);
            basicConstraints.setEnabled(true);
            basicConstraints.setPathLenConstraint(12345);

            credentialManagerCertificateExtensions.setBasicConstraints(basicConstraints);
            /*
             * prepare key Usage extension
             */
            if (fillKeyusage == true) {

                final CredentialManagerKeyUsage keyUsage = new CredentialManagerKeyUsage();

                final List<CredentialManagerKeyUsageType> keyUsageType = new ArrayList<CredentialManagerKeyUsageType>();

                keyUsageType.add(CredentialManagerKeyUsageType.DIGITAL_SIGNATURE);
                keyUsageType.add(CredentialManagerKeyUsageType.ENCIPHER_ONLY);
                keyUsageType.add(CredentialManagerKeyUsageType.CRL_SIGN);
                keyUsageType.add(CredentialManagerKeyUsageType.DATA_ENCIPHERMENT);
                keyUsageType.add(CredentialManagerKeyUsageType.DECIPHER_ONLY);
                keyUsageType.add(CredentialManagerKeyUsageType.KEY_AGREEMENT);
                keyUsageType.add(CredentialManagerKeyUsageType.KEY_CERT_SIGN);
                keyUsageType.add(CredentialManagerKeyUsageType.KEY_ENCIPHERMENT);
                keyUsageType.add(CredentialManagerKeyUsageType.NON_REPUDIATION);

                keyUsage.setKeyUsageType(keyUsageType);

                credentialManagerCertificateExtensions.setKeyUsage(keyUsage);

            }

            /*
             * prepare Extended key Usage extension
             */
            if (fillExtendedKeyUsage == true) {

                final CredentialManagerExtendedKeyUsage extendedKeyUsage = new CredentialManagerExtendedKeyUsage();

                extendedKeyUsage.setCritical(false);

                final List<CredentialManagerKeyPurposeId> keyPurposeId = new ArrayList<CredentialManagerKeyPurposeId>();

                keyPurposeId.add(CredentialManagerKeyPurposeId.ID_KP_CLIENT_AUTH);
                keyPurposeId.add(CredentialManagerKeyPurposeId.ID_KP_CODE_SIGNING);
                keyPurposeId.add(CredentialManagerKeyPurposeId.ID_KP_EMAIL_PROTECTION);
                keyPurposeId.add(CredentialManagerKeyPurposeId.ID_KP_OCSP_SIGNING);
                keyPurposeId.add(CredentialManagerKeyPurposeId.ID_KP_SERVER_AUTH);
                keyPurposeId.add(CredentialManagerKeyPurposeId.ID_KP_TIMESTAMPING);

                extendedKeyUsage.setKeyPurposeId(keyPurposeId);

                credentialManagerCertificateExtensions.setExtendedKeyUsage(extendedKeyUsage);

            }

            /*
             * prepare Subject Key Identifier extension
             */
            if (fillSubjectKeyIdentifier == true) {

                final CredentialManagerSubjectKeyIdentifier subjectKeyIdentifier = new CredentialManagerSubjectKeyIdentifier();

                subjectKeyIdentifier.setCritical(false);

                subjectKeyIdentifier.setKeyIdentifierAlgorithm("160-BIT_SHA-1");

                credentialManagerCertificateExtensions.setSubjectKeyIdentifier(subjectKeyIdentifier);
            }

            profileInfo.setExtentionAttributes(credentialManagerCertificateExtensions);

        }

        return profileInfo;

    }
}
