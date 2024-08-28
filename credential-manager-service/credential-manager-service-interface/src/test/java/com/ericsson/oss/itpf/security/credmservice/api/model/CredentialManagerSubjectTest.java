/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.api.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class CredentialManagerSubjectTest {

    @Test
    public void testUpdateAllFieldByString() {
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.updateFromSubjectDN("CN=paola, SURNAME=zerega, C=italia, L=liguria, ST=genova, STREET=Via Melen 77, OU=ENM, O=Ericsson, DN=pippo, T=subject, GIVENNAME=melania, SN=123456789");
        assertEquals("paola", subject.getCommonName());
        assertEquals("zerega", subject.getSurName());
        assertEquals("italia", subject.getCountryName());
        assertEquals("liguria", subject.getLocalityName());
        assertEquals("genova", subject.getStateOrProvinceName());
        assertEquals("Via Melen 77", subject.getStreetAddress());
        assertEquals("ENM", subject.getOrganizationalUnitName());
        assertEquals("Ericsson", subject.getOrganizationName());
        assertEquals("pippo", subject.getDnQualifier());
        assertEquals("subject", subject.getTitle());
        assertEquals("melania", subject.getGivenName());
        assertEquals("123456789", subject.getSerialNumber());
    }

    @Test
    public void testUpdatePartiallyFieldByString() {
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setLocalityName("liguria");
        subject.setCountryName("italia");
        subject.setStateOrProvinceName("genova");
        subject.setStreetAddress("Via Melen 77");
        subject.setOrganizationalUnitName("ENM");
        subject.setOrganizationName("Ericsson");
        subject.setGivenName("xavier");
        subject.updateFromSubjectDN("CN=paola, SURNAME=zerega, DN=pippo, T=subject, GIVENNAME=melania, SN=123456789");
        assertEquals("paola", subject.getCommonName());
        assertEquals("zerega", subject.getSurName());
        assertEquals("italia", subject.getCountryName());
        assertEquals("liguria", subject.getLocalityName());
        assertEquals("genova", subject.getStateOrProvinceName());
        assertEquals("Via Melen 77", subject.getStreetAddress());
        assertEquals("ENM", subject.getOrganizationalUnitName());
        assertEquals("Ericsson", subject.getOrganizationName());
        assertEquals("pippo", subject.getDnQualifier());
        assertEquals("subject", subject.getTitle());
        assertEquals("melania", subject.getGivenName());
        assertEquals("123456789", subject.getSerialNumber());
    }

    @Test
    public void testGetSubjectDN() {
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        final String subjectDN = "CN=paola,SURNAME=zerega,C=italia,L=liguria,ST=genova,STREET=Via Melen 77,OU=ENM,O=Ericsson,DN=pippo,T=subject,GIVENNAME=melania,SN=123456789";
        subject.updateFromSubjectDN(subjectDN);
        assertEquals(subjectDN, subject.retrieveSubjectDN());
    }

    @Test
    public void testGetSubjectDNWithoutCN() {
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        final String subjectDN = "SURNAME=zerega,C=italia,L=liguria,ST=genova,STREET=Via Melen 77,OU=ENM,O=Ericsson,DN=pippo,T=subject,GIVENNAME=melania,SN=123456789";
        subject.updateFromSubjectDN(subjectDN);
        assertEquals(subjectDN, subject.retrieveSubjectDN());
    }

    @Test
    public void testX509Name() {
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setLocalityName("liguria");
        subject.setCountryName("italia");
        subject.setStateOrProvinceName("genova");
        subject.setStreetAddress("Via Melen 77");
        subject.setOrganizationalUnitName("ENM");
        subject.setOrganizationName("Ericsson");
        subject.setGivenName("xavier");
        subject.setDnQualifier("pipino");
        final X509Name x509Name = new X509Name(subject.retrieveSubjectDN());
        assertNotNull(x509Name);
    }

    @Test
    public void testX509Principal() {
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setLocalityName("liguria");
        subject.setCountryName("italia");
        subject.setStateOrProvinceName("genova");
        subject.setStreetAddress("Via Melen 77");
        subject.setOrganizationalUnitName("ENM");
        subject.setOrganizationName("Ericsson");
        subject.setGivenName("xavier");
        subject.setDnQualifier("pipino");
        final X509Principal x509Name = new X509Principal(subject.retrieveSubjectDN());
        assertNotNull(x509Name);
        //        final X500Principal x500Name = new X500Principal(subject.getSubjectDN());
        //        assertNotNull(x509Name);
    }
    
    @Test
    public void testEquals() {
        CredentialManagerSubject subj1 = new CredentialManagerSubject();
        CredentialManagerSubject subj2 = new CredentialManagerSubject();
        assertTrue(!subj2.equals(null));
        assertTrue(!subj2.equals("wrongObject"));
        assertTrue(subj2.equals(subj1));
        subj1.setCommonName("cn=abc");
        subj1.setCountryName("SE");
        subj1.setDnQualifier("cn=123");
        subj1.setGivenName("givname");
        subj1.setLocalityName("loc");
        subj1.setOrganizationalUnitName("ou");
        subj1.setOrganizationName("org");
        subj1.setSerialNumber("123");
        subj1.setStateOrProvinceName("state");
        subj1.setStreetAddress("address");
        subj1.setSurName("surr");
        subj1.setTitle("title");
        assertTrue(subj2.hashCode() != subj1.hashCode());
        assertTrue(!subj2.equals(subj1));
        subj2.setCommonName("cn=abc");
        assertTrue(!subj2.equals(subj1));
        subj2.setCountryName("SE");
        assertTrue(!subj2.equals(subj1));
        subj2.setDnQualifier("cn=123");
        assertTrue(!subj2.equals(subj1));
        subj2.setGivenName("givname");
        assertTrue(!subj2.equals(subj1));
        subj2.setLocalityName("loc");
        assertTrue(!subj2.equals(subj1));
        subj2.setOrganizationalUnitName("ou");
        assertTrue(!subj2.equals(subj1));
        subj2.setOrganizationName("org");
        assertTrue(!subj2.equals(subj1));
        subj2.setSerialNumber("123");
        assertTrue(!subj2.equals(subj1));
        subj2.setStateOrProvinceName("state");
        assertTrue(!subj2.equals(subj1));
        subj2.setStreetAddress("address");
        assertTrue(!subj2.equals(subj1));
        subj2.setSurName("surr");
        assertTrue(!subj2.equals(subj1));
        subj2.setTitle("title");
        assertTrue(subj2.equals(subj1));
    }

}
