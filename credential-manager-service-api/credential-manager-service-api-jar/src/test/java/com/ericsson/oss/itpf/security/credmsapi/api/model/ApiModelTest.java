package com.ericsson.oss.itpf.security.credmsapi.api.model;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class ApiModelTest {

    @Test
    public void CertificateFormatTest() {
        final CertificateFormat cert = CertificateFormat.BASE_64;
        assertTrue(cert.toString().equals("BASE_64"));
        assertTrue(CertificateFormat.PKCS12 == CertificateFormat.valueOf("PKCS12"));
        assertTrue(CertificateFormat.JCEKS != CertificateFormat.valueOf("JKS"));
        try {
            CertificateFormat.valueOf("fakeValue");
            assertTrue(false);
        } catch (final IllegalArgumentException e) {
            assertTrue(true);
        }
    }
    
    @Test
    public void CrlReasonTest() {
        final CrlReason cr = CrlReason.CERTIFICATE_HOLD;
        assertTrue(cr.toString().equals("CERTIFICATE_HOLD"));
        assertTrue(CrlReason.PRIVILEGE_WITHDRAWN == CrlReason.valueOf("PRIVILEGE_WITHDRAWN"));
        assertTrue(CrlReason.CA_COMPROMISE != CrlReason.valueOf("AFFILIATION_CHANGED"));
        try {
            CrlReason.valueOf("fakeValue");
            assertTrue(false);
        } catch (final IllegalArgumentException e) {
            assertTrue(true);
        }
    }
    
    @Test
    public void CredentialManagerCertificateExtensionImplTest() {
        CredentialManagerCertificateExtensionImpl crtext = new CredentialManagerCertificateExtensionImpl("wrongObject");
        assertTrue(crtext != null);
    }
    
    @Test
    public void CsrFormatTest() {
        final CsrFormat cf = CsrFormat.BASE_64;
        assertTrue(cf.toString().equals("BASE_64"));
        assertTrue(CsrFormat.JCEKS == CsrFormat.valueOf("JCEKS"));
        assertTrue(CsrFormat.values().length == 4);
        try {
            CsrFormat.valueOf("fakeValue");
            assertTrue(false);
        } catch (final IllegalArgumentException e) {
            assertTrue(true);
        }
    }
    
    @SuppressWarnings("static-access")
    @Test
    public void EntitySummaryTest() {
        final Subject sub = new Subject();
        sub.setCommonName("cn");
        final EntitySummary es = new EntitySummary("name", EntityStatus.ACTIVE, sub);
        assertTrue(es.getName().equals("name"));
        es.setName("eman");
        assertTrue(!es.getName().equals("name"));
        assertTrue(es.getStatus() == EntityStatus.ACTIVE);
        es.setStatus(EntityStatus.NEW);
        assertTrue(es.getStatus() != EntityStatus.ACTIVE);
        assertTrue(es.getSubject().getCommonName().equals("cn"));
        es.setSubject(null);
        assertTrue(es.getSubject() != new Subject());
        assertTrue(EntitySummary.getSerialversionuid() != 0);
        assertTrue(Subject.getSerialversionuid() == es.getSubject().getSerialversionuid());
    }
    
    @Test
    public void SubjectTest() {
        final Subject sub = new Subject();
        sub.setCommonName("cn");
        sub.setCountryName("co");
        sub.setDnQualifier("dn");
        sub.setGivenName("gn");
        sub.setLocalityName("ln");
        sub.setOrganizationalUnitName("ou");
        sub.setOrganizationName("o");
        sub.setSerialNumber("sn");
        sub.setStateOrProvinceName("sp");
        sub.setStreetAddress("st");
        sub.setSurName("su");
        sub.setTitle("t");
        assertTrue(sub.getCommonName().equals("cn"));
        assertTrue(sub.getCountryName().equals("co"));
        assertTrue(sub.getDnQualifier().equals("dn"));
        assertTrue(sub.getGivenName().equals("gn"));
        assertTrue(sub.getLocalityName().equals("ln"));
        assertTrue(sub.getOrganizationalUnitName().equals("ou"));
        assertTrue(sub.getOrganizationName().equals("o"));
        assertTrue(sub.getSerialNumber().equals("sn"));
        assertTrue(sub.getStateOrProvinceName().equals("sp"));
        assertTrue(sub.getStreetAddress().equals("st"));
        assertTrue(sub.getSurName().equals("su"));
        assertTrue(sub.getTitle().equals("t"));
    }
    
    @Test
    public void TrustFormatTest() {
        final TrustFormat tf = TrustFormat.BASE_64;
        assertTrue(tf.toString().equals("BASE_64"));
        assertTrue(TrustFormat.JCEKS == TrustFormat.valueOf("JCEKS"));
        assertTrue(TrustFormat.values().length == 5);
        try {
            TrustFormat.valueOf("fakeValue");
            assertTrue(false);
        } catch (final IllegalArgumentException e) {
            assertTrue(true);
        }
    }
    
    @Test
    public void TrustSourceTest() {
        final TrustSource ts = TrustSource.BOTH;
        assertTrue(ts.toString().equals("BOTH"));
        assertTrue(TrustSource.EXTERNAL == TrustSource.valueOf("EXTERNAL"));
        assertTrue(TrustSource.values().length == 3);
        try {
            TrustSource.valueOf("fakeValue");
            assertTrue(false);
        } catch (final IllegalArgumentException e) {
            assertTrue(true);
        }
    }
    
}
