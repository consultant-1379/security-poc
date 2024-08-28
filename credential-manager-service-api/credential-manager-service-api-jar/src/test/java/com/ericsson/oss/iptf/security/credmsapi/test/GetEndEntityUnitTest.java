package com.ericsson.oss.iptf.security.credmsapi.test;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.SANConvertHandler;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEdiPartyName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerOtherName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;

@RunWith(JUnit4.class)
public class GetEndEntityUnitTest {

    private static final Logger LOG = LogManager.getLogger(GetEndEntityUnitTest.class);

    @Test
    public void testSubjectAltName() {

        final SubjectAlternativeNameType subjectAltNameXml = prepareParametersXML();
        final CredentialManagerSubjectAltName subjectAltNameXmlResult = prepareResultXML();
        final CredentialManagerProfileInfo profileInfo = prepareParametersProfile();

        /*
         * Invoke generateDERAttributes method of CSRAttributesHandler class
         */
        try {
            final SANConvertHandler convertHandler = new SANConvertHandler();
            final CredentialManagerSubjectAltName cmSubjectAltName = convertHandler.setSubjectAltName(subjectAltNameXml, profileInfo);

            // assertTrue("attributes from Profile and XML are equal",
            // cmSubjectAltName.equals(subjectAltNameXmlResult));
            assertTrue("attributes getDirectoryName from Profile and XML are equal", cmSubjectAltName.getDirectoryName().equals(subjectAltNameXmlResult.getDirectoryName()));

            assertTrue("attributes getDNSName from Profile and XML are equal", cmSubjectAltName.getDNSName().equals(subjectAltNameXmlResult.getDNSName()));

            assertTrue("attributes getEdiPartyName from Profile and XML are equal", cmSubjectAltName.getEdiPartyName().equals(subjectAltNameXmlResult.getEdiPartyName()));

            assertTrue("attributes getIPAddress from Profile and XML are equal", cmSubjectAltName.getIPAddress().equals(subjectAltNameXmlResult.getIPAddress()));

            assertTrue("attributes getOtherName getTypeId from Profile and XML are equal",
                    cmSubjectAltName.getOtherName().get(0).getTypeId().equals(subjectAltNameXmlResult.getOtherName().get(0).getTypeId()));
            assertTrue("attributes getOtherName getValue from Profile and XML are equal",
                    cmSubjectAltName.getOtherName().get(0).getValue().equals(subjectAltNameXmlResult.getOtherName().get(0).getValue()));
            assertTrue("attributes getRegisteredID from Profile and XML are equal", cmSubjectAltName.getRegisteredID().equals(subjectAltNameXmlResult.getRegisteredID()));

            assertTrue("attributes getRfc822Name from Profile and XML are equal", cmSubjectAltName.getRfc822Name().equals(subjectAltNameXmlResult.getRfc822Name()));

            assertTrue("attributes getUniformResourceIdentifier from Profile and XML are equal",
                    cmSubjectAltName.getUniformResourceIdentifier().equals(subjectAltNameXmlResult.getUniformResourceIdentifier()));

            assertTrue("attributes getX400Address from Profile and XML are equal", cmSubjectAltName.getX400Address().equals(subjectAltNameXmlResult.getX400Address()));

        } catch (final IssueCertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        final SANConvertHandler convertHandler = new SANConvertHandler();
        try {
            final CredentialManagerSubjectAltName cmSubjectAltName = convertHandler.setSubjectAltName(null, profileInfo);
            assertTrue(cmSubjectAltName.getDNSName().get(0).equals("dns"));
        } catch (IssueCertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        CredentialManagerProfileInfo prInfo = profileInfo;
        List<CredentialManagerEdiPartyName> ediPartyName = new ArrayList<CredentialManagerEdiPartyName>();
        ediPartyName.add(new CredentialManagerEdiPartyName());
        prInfo.getSubjectDefaultAlternativeName().setEdiPartyName(ediPartyName);
        List<String> rfc822Name = new ArrayList<String>();
        rfc822Name.add("testRfc822");
        prInfo.getSubjectDefaultAlternativeName().setRfc822Name(rfc822Name);
        List<String> x400Address = new ArrayList<String>();
        x400Address.add("testX400Address");
        prInfo.getSubjectDefaultAlternativeName().setX400Address(x400Address);
        
        SubjectAlternativeNameType sanXML = new SubjectAlternativeNameType();
        
        final SANConvertHandler cH = new SANConvertHandler();
        try {
            final CredentialManagerSubjectAltName cmSANTest = cH.setSubjectAltName(sanXML, prInfo);
            assertTrue(cmSANTest.getDirectoryName().equals(prInfo.getSubjectDefaultAlternativeName().getDirectoryName()));
            assertTrue(cmSANTest.getDNSName().equals(prInfo.getSubjectDefaultAlternativeName().getDNSName()));
            assertTrue(cmSANTest.getEdiPartyName().equals(prInfo.getSubjectDefaultAlternativeName().getEdiPartyName()));
            assertTrue(cmSANTest.getIPAddress().equals(prInfo.getSubjectDefaultAlternativeName().getIPAddress()));
            assertTrue(cmSANTest.getOtherName().equals(prInfo.getSubjectDefaultAlternativeName().getOtherName()));
            assertTrue(cmSANTest.getRegisteredID().equals(prInfo.getSubjectDefaultAlternativeName().getRegisteredID()));
            assertTrue(cmSANTest.getRfc822Name().equals(prInfo.getSubjectDefaultAlternativeName().getRfc822Name()));
            assertTrue(cmSANTest.getUniformResourceIdentifier().equals(prInfo.getSubjectDefaultAlternativeName().getUniformResourceIdentifier()));      
            assertTrue(cmSANTest.getX400Address().equals(prInfo.getSubjectDefaultAlternativeName().getX400Address()));      
        } catch (IssueCertificateException e) {
            assertTrue(false);
        }

    }

    @Test
    public void testSubjectAltNameNull() {
        try {
            final SANConvertHandler convertHandler = new SANConvertHandler();
            final CredentialManagerSubjectAltName cmSubjectAltName = convertHandler.setSubjectAltName(null, null);
        } catch (final IssueCertificateException e) {
            // TODO Auto-generated catch block
            // e.printStackTrace();
            assert (true);
        }

    }

    @Test
    public void testIsSubjectAltNameEmpty() {

        final SANConvertHandler convertHandler = new SANConvertHandler();

        SubjectAlternativeNameType subjectAltName = null;
        
        assertTrue(convertHandler.isSubjectAltNameEmpty(subjectAltName));
        
        subjectAltName = new SubjectAlternativeNameType();

        final List<String> names = new ArrayList<String>();
        names.add("name");

        // test Directoryname
        subjectAltName.setDirectoryname(names);
        assertTrue("Directoryname empty", !convertHandler.isSubjectAltNameEmpty(subjectAltName));
        subjectAltName.setDirectoryname(null);

        // testcase Dns
        subjectAltName.setDns(names);
        assertTrue("Dns empty", !convertHandler.isSubjectAltNameEmpty(subjectAltName));
        subjectAltName.setDns(null);

        // testcase Email
        subjectAltName.setEmail(names);
        assertTrue("Email empty", !convertHandler.isSubjectAltNameEmpty(subjectAltName));
        subjectAltName.setEmail(null);

        // testcase Ipaddress
        subjectAltName.setIpaddress(names);
        assertTrue("Ipaddress empty", !convertHandler.isSubjectAltNameEmpty(subjectAltName));
        subjectAltName.setIpaddress(null);

        // testcase Registeredid
        subjectAltName.setRegisteredid(names);
        assertTrue("Registeredid empty", !convertHandler.isSubjectAltNameEmpty(subjectAltName));
        subjectAltName.setRegisteredid(null);

        // testcase Uri
        subjectAltName.setUri(names);
        assertTrue("Uri empty", !convertHandler.isSubjectAltNameEmpty(subjectAltName));
        subjectAltName.setUri(null);

        // testcase Othername
        subjectAltName.setOthername(names);
        assertTrue("Othername empty", !convertHandler.isSubjectAltNameEmpty(subjectAltName));
        subjectAltName.setOthername(null);

        assertTrue("subjectAltName not empty", convertHandler.isSubjectAltNameEmpty(subjectAltName));
    }

    private SubjectAlternativeNameType prepareParametersXML() {

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

        final List<String> email = new ArrayList<String>();
        email.add("NAME@ericsson.com");
        subjectAltNameXml.setEmail(email);

        final List<String> ipaddress = new ArrayList<String>();
        ipaddress.add("1.1.1.1");
        subjectAltNameXml.setIpaddress(ipaddress);

        final List<String> othername = new ArrayList<String>();
        othername.add("othername");
        subjectAltNameXml.setOthername(othername);

        final List<String> registerid = new ArrayList<String>();
        registerid.add("registerid");
        subjectAltNameXml.setRegisteredid(registerid);

        final List<String> uri = new ArrayList<String>();
        uri.add("uri");
        subjectAltNameXml.setUri(uri);

        return subjectAltNameXml;

    }

    private CredentialManagerSubjectAltName prepareResultXML() {

        final CredentialManagerSubjectAltName subjectDefaultAlternativeName = new CredentialManagerSubjectAltName();

        final List<String> directoryName = new ArrayList<String>();
        directoryName.add("DN=HOST_NAME");
        subjectDefaultAlternativeName.setDirectoryName(directoryName);

        final List<String> dns = new ArrayList<String>();
        dns.add("dns");
        subjectDefaultAlternativeName.setDNSName(dns);

        final List<String> email = new ArrayList<String>();
        email.add("NAME@ericsson.com");
        subjectDefaultAlternativeName.setX400Address(email);

        final List<String> ipaddress = new ArrayList<String>();
        ipaddress.add("1.1.1.1");
        subjectDefaultAlternativeName.setIPAddress(ipaddress);

        final List<CredentialManagerOtherName> othername = new ArrayList<CredentialManagerOtherName>();
        final CredentialManagerOtherName element = new CredentialManagerOtherName();
        element.setValue("othername");
        element.setTypeId("");
        othername.add(element);
        subjectDefaultAlternativeName.setOtherName(othername);

        final List<String> registerid = new ArrayList<String>();
        registerid.add("registerid");
        subjectDefaultAlternativeName.setRegisteredID(registerid);

        final List<String> uri = new ArrayList<String>();
        uri.add("uri");
        subjectDefaultAlternativeName.setUniformResourceIdentifier(uri);

        return subjectDefaultAlternativeName;

    }

    private CredentialManagerProfileInfo prepareParametersProfile() {

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

        final List<String> email = new ArrayList<String>();
        email.add("NAME@ericsson.com");
        subjectDefaultAlternativeName.setX400Address(email);

        final List<String> ipaddress = new ArrayList<String>();
        ipaddress.add("1.1.1.1");
        subjectDefaultAlternativeName.setIPAddress(ipaddress);

        final List<CredentialManagerOtherName> othername = new ArrayList<CredentialManagerOtherName>();
        final CredentialManagerOtherName element = new CredentialManagerOtherName();
        element.setValue("othername");
        element.setTypeId("");
        othername.add(element);
        subjectDefaultAlternativeName.setOtherName(othername);

        final List<String> registerid = new ArrayList<String>();
        registerid.add("registerid");
        subjectDefaultAlternativeName.setRegisteredID(registerid);

        final List<String> uri = new ArrayList<String>();
        uri.add("uri");
        subjectDefaultAlternativeName.setUniformResourceIdentifier(uri);

        profileInfo.setSubjectDefaultAlternativeName(subjectDefaultAlternativeName);

        return profileInfo;

    }

}
