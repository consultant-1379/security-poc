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
package com.ericsson.oss.itpf.security.credmservice.api.model;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Assert;
import org.junit.Test;
import com.ericsson.oss.itpf.security.credmservice.test.util.EqualsAndHashTester;
import com.ericsson.oss.itpf.security.credmservice.test.util.JavaBeanTester;

public class ApiModelTest {

    @Test
    public void beanTest() {
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerEntity());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerAuthorityInformationAccess());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerAuthorityKeyIdentifier());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerBasicConstraints());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerCertificateExtensions());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerCRLDistributionPoint());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerCRLDistributionPoints());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerDistributionPointName());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerEdiPartyName());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerKeyUsage());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerOtherName());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerProfileInfo());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerSubjectAltName());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerExtendedKeyUsage());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerSubject());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerAccessDescription());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerAlgorithm());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerSubjectKeyIdentifier());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerCertificateAuthority("pippo"));
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerCertificateIdentifier());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerPIBParameters());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CredentialManagerTrustCA(null, false));
    }

    @Test
    public void equalsAndHashCodeTests() {
        EqualsAndHashTester.testEqualsAndHash(CredentialManagerSubject.class);
        EqualsAndHashTester.testEqualsAndHash(CredentialManagerCertificateIdentifier.class);
    }

    @Test
    public void beanTestNotNullGetMethods() {
        final CredentialManagerSubjectAltName credentialManagerSubjectAltName = new CredentialManagerSubjectAltName();

        Assert.assertNotNull(credentialManagerSubjectAltName);

        final CredentialManagerKeyUsage credentialManagerKeyUsageBean = new CredentialManagerKeyUsage();
        Assert.assertNotNull(credentialManagerKeyUsageBean.getKeyUsageType());

        final CredentialManagerExtendedKeyUsage credentialManagerExtendedKeyUsageBean = new CredentialManagerExtendedKeyUsage();
        Assert.assertNotNull(credentialManagerExtendedKeyUsageBean.getKeyPurposeId());
    }
    
    @Test
    public void testCredentialManagerAlgorithm() {
        CredentialManagerAlgorithm alg1 = new CredentialManagerAlgorithm();
        assertTrue(!alg1.equals(null));
        CredentialManagerAlgorithm alg2 = new CredentialManagerAlgorithm();
        alg2.setId(1);
        assertTrue(!alg1.equals(alg2));
        alg1.setId(1);
        alg2.setKeySize(12);
        assertTrue(!alg1.equals(alg2));
        alg1.setKeySize(11);
        assertTrue(!alg1.equals(alg2));
        alg1.setKeySize(12);
        alg2.setName("alg2");
        assertTrue(!alg1.equals(alg2));
        alg1.setName("alg1");
        assertTrue(!alg1.equals(alg2));
        alg1.setName("alg2");
        alg2.setOid("oid2");
        assertTrue(!alg1.equals(alg2));
        alg1.setOid("oid1");
        assertTrue(!alg1.equals(alg2));
        alg1.setOid("oid2");
        alg2.setSupported(true);
        assertTrue(!alg1.equals(alg2));
        alg1.setSupported(false);
        alg1.setSupported(true);
        alg2.setType(CredentialManagerAlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        alg1.setType(CredentialManagerAlgorithmType.MESSAGE_DIGEST_ALGORITHM);
        assertTrue(!alg1.equals(alg2));
        alg1.setType(CredentialManagerAlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        assertTrue(alg1.equals(alg2));
        
        assertTrue(alg2.toString().contains("Algorithm"));
        assertTrue(alg1.hashCode()==alg2.hashCode());
        alg1.setKeySize(null);
        alg2.setKeySize(null);
        alg1.setOid(null);
        alg2.setOid(null);
        alg1.setName(null);
        alg2.setName(null);
        assertTrue(alg1.equals(alg2));
        alg1.setSupported(false);
        alg2.setSupported(false);
        alg1.setType(null);
        alg2.setType(null);
        assertTrue(alg1.hashCode()==alg2.hashCode());
    }
    
    @Test 
    public void testCredentialManagerCertificateAuthority() {
        CredentialManagerCertificateAuthority ca1 = new CredentialManagerCertificateAuthority ("ca1");
        assertTrue(ca1.getSimpleName().equals("ca1"));
        CredentialManagerCertificateAuthority ca2 = null;
        assertTrue(!ca1.equals(ca2));
        ca2 = new CredentialManagerCertificateAuthority ("ca2");
        ca1 = new CredentialManagerCertificateAuthority ("ca2");
        assertTrue(ca1.equals(ca2));
        ca1=ca2;
        assertTrue(ca1.equals(ca2));
        assertTrue(ca1.hashCode()==ca2.hashCode());
        X500Name x500 = new X500Name("CN=ca3");
        CredentialManagerCertificateAuthority ca3 = new CredentialManagerCertificateAuthority(x500,"ca3");
        ca3.setCertChainSerializable(null);
        assertTrue(ca3.getCertChainSerializable() == null);
        assertTrue(!ca3.equals(123));
    }
    
    @Test
    public void testCredentialManagerAlgorithmType() {
        CredentialManagerAlgorithmType algType = CredentialManagerAlgorithmType.ASYMMETRIC_KEY_ALGORITHM;
        assertTrue(algType.getId() == 3 );
        assertTrue(algType.value().equals("asymmetric key algorithm"));
        assertTrue(CredentialManagerAlgorithmType.getType(null) == null);
        assertTrue(CredentialManagerAlgorithmType.getType(1) == CredentialManagerAlgorithmType.MESSAGE_DIGEST_ALGORITHM);
        assertTrue(CredentialManagerAlgorithmType.getType(2) == CredentialManagerAlgorithmType.SIGNATURE_ALGORITHM);
        assertTrue(CredentialManagerAlgorithmType.getType(3) == CredentialManagerAlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        assertTrue(CredentialManagerAlgorithmType.getType(4) == CredentialManagerAlgorithmType.SYMMETRIC_KEY_ALGORITHM);
        try {
            CredentialManagerAlgorithmType.getType(12);
            assertTrue(false);
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("No matching type for id 12"));
        }

    }
    
    @Test
    public void testCredentialManagerCertificateIdentifier() {
        CredentialManagerCertificateIdentifier certId = new CredentialManagerCertificateIdentifier(new X500Principal("CN=certId"),new X500Principal("CN=issuerCertId"),BigInteger.ONE);
        assertTrue(certId.getSubjectDN().equals(new X500Principal("CN=certId")));
        CredentialManagerCertificateIdentifier certId2 = new CredentialManagerCertificateIdentifier();
        CredentialManagerCertificateIdentifier certId3 = new CredentialManagerCertificateIdentifier();
        assertTrue(certId.hashCode() != certId2.hashCode());
        assertTrue(certId.equals(certId));
        assertTrue(!certId.equals(null));
        assertTrue(!certId.equals("wrongObject"));
        assertTrue(!certId2.equals(certId));
        assertTrue(certId2.equals(certId3));
        CredentialManagerCertificateIdentifier certId4 = new CredentialManagerCertificateIdentifier(new X500Principal("CN=certId"),new X500Principal("CN=issuerCertId"),BigInteger.ONE);
        assertTrue(certId4.equals(certId));
        CredentialManagerCertificateIdentifier certId5 = new CredentialManagerCertificateIdentifier(new X500Principal("CN=certId5"),new X500Principal("CN=issuerCertId"),BigInteger.ONE);
        assertTrue(!certId5.equals(certId));
        CredentialManagerCertificateIdentifier certId6 = new CredentialManagerCertificateIdentifier(new X500Principal("CN=certId"),new X500Principal("CN=issuerCertId6"),BigInteger.ONE);
        assertTrue(!certId6.equals(certId));
        CredentialManagerCertificateIdentifier certId7 = new CredentialManagerCertificateIdentifier(new X500Principal("CN=certId"),new X500Principal("CN=issuerCertId"),BigInteger.TEN);
        assertTrue(!certId7.equals(certId));
    }
    
    @Test
    public void testCredentialManagerCertificateStatus() {
        CredentialManagerCertificateStatus credStatus = CredentialManagerCertificateStatus.ACTIVE;
        assertTrue(credStatus.value().equals("ACTIVE"));
        assertTrue(CredentialManagerCertificateStatus.fromValue("ACTIVE").equals(credStatus));
    }

    @Test
    public void testCredentialManagerCrlMaps() {
        CredentialManagerCrlMaps crlMaps = new CredentialManagerCrlMaps();
        assertTrue(crlMaps.getExternalCACrlMap() != null && crlMaps.getInternalCACrlMap() != null);
    }
    
    @Test
    public void testCredentialManagerEntityCertificates() {
        CredentialManagerEntityCertificates entCerts = new CredentialManagerEntityCertificates();
        assertTrue(entCerts.toString().contains("EntityProfileName"));
    }
    
    @Test
    public void testCredentialManagerEntityStatus() {
        CredentialManagerEntityStatus entStatus = CredentialManagerEntityStatus.REISSUE;
        assertTrue(entStatus.value().equals("REISSUE"));
        assertTrue(CredentialManagerEntityStatus.fromValue("REISSUE").equals(entStatus));
    }
    
    @Test
    public void testCredentialManagerEntityType() {
        CredentialManagerEntityType entType = CredentialManagerEntityType.ENTITY;
        assertTrue(entType.toString().equals("entity"));
        assertTrue(CredentialManagerEntityType.fromString("ENTITY").equals(entType));
        assertTrue(CredentialManagerEntityType.fromString(null) == null);
    }
    
    @Test
    public void testCredentialManagerKeyPurposeId() {
        try {
            CredentialManagerKeyPurposeId.fromValue("wrongEnumEntry");
            assertTrue(false);
        } catch (IllegalArgumentException e) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testCredentialManagerKeyUsageType() {
        try {
            CredentialManagerKeyUsageType.fromValue("wrongEnumEntry");
            assertTrue(false);
        } catch (IllegalArgumentException e) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testCredentialManagerProfileType() {
        CredentialManagerProfileType profType = CredentialManagerProfileType.CERTIFICATE_PROFILE;
        assertTrue(profType.getValue().equals("certificateprofile"));
        assertTrue(profType.toString().equals("CERTIFICATE_PROFILE"));
        assertTrue(CredentialManagerProfileType.fromValue("trustprofile").equals(CredentialManagerProfileType.TRUST_PROFILE));
        try {
            CredentialManagerProfileType.fromValue("wrongType");
            assertTrue(false);
        } catch (IllegalArgumentException e) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testCredentialManagerReasonFlag() {
        CredentialManagerReasonFlag rflag = CredentialManagerReasonFlag.CA_COMPROMISE;
        assertTrue(rflag.value().equals("cACompromise"));
        assertTrue(rflag.toString().equals("CA_COMPROMISE"));
        try {
            CredentialManagerReasonFlag.fromValue("wrongFlag");
            assertTrue(false);
        } catch (IllegalArgumentException e) {
            assertTrue(true);
        }
        assertTrue(CredentialManagerReasonFlag.fromValue("unused").equals(CredentialManagerReasonFlag.UNUSED));
    }
    
    @Test
    public void testCredentialManagerTrustMaps() {
        CredentialManagerTrustMaps cmTM = new CredentialManagerTrustMaps();
        CredentialManagerTrustCA key1 = new CredentialManagerTrustCA("key1",false);
        Map<String,CredentialManagerCertificateAuthority> extTMap = new HashMap<String,CredentialManagerCertificateAuthority>();
        extTMap.put("key1", new CredentialManagerCertificateAuthority("Extca1"));
        cmTM.setExternalCATrustMap(extTMap);
        assertTrue(cmTM.getExternalCATrustMap().get("key1").equals(new CredentialManagerCertificateAuthority("Extca1")));
        Map<String,CredentialManagerCertificateAuthority> intTMap = new HashMap<String,CredentialManagerCertificateAuthority>();
        CredentialManagerTrustCA key2 = new CredentialManagerTrustCA("key2",false);
        intTMap.put("key2", new CredentialManagerCertificateAuthority("Intca2"));
        cmTM.setInternalCATrustMap(intTMap);
        assertTrue(cmTM.getInternalCATrustMap().get("key2").equals(new CredentialManagerCertificateAuthority("Intca1")));
    }
    
    @Test
    public void testCredentialManagerX500Name() throws IOException {
        X500Name x500n1 = new X500Name("CN=testCN1, O=orgTest1");
        CredentialManagerX500Name cmx500Name1 = new CredentialManagerX500Name(x500n1);
        assertNotNull(cmx500Name1.toASN1Primitive());
	assertNotNull(cmx500Name1.toASN1Object());
        assertNotNull(cmx500Name1.hashCode());
        assertNotNull(cmx500Name1.getDEREncoded());
        assertNotNull(cmx500Name1.getEncoded());
        assertNotNull(cmx500Name1.getEncoded(ASN1Encoding.DER));
        try {
            cmx500Name1.clone();
            assertTrue(false);
        } catch (CloneNotSupportedException e) {
            assertTrue(true);
        }
        assertTrue(cmx500Name1.toString().equals("CN=testCN1,O=orgTest1")); //spaces are trimmed
        CredentialManagerX500Name cmx500Name2 = new CredentialManagerX500Name("CN=testCN1,O=orgTest1");
        assertTrue(cmx500Name2.equals(cmx500Name1));
        try {
            cmx500Name1.finalize();
            assertTrue(true);
        } catch (Throwable e) {
            assertTrue(false);
        }
    }
    
    @Test
    public void testEqualOnlyCredentialManagerTrustCA() {
        CredentialManagerTrustCA tCA1 = new CredentialManagerTrustCA("tCA1", false);
        CredentialManagerTrustCA tCA2 = new CredentialManagerTrustCA("tCA2", true);
        assertTrue(!tCA1.equals(tCA2));
        tCA2.setChainRequired(false);
        assertTrue(!tCA1.equals(tCA2));
        tCA2.setTrustCAName(tCA1.getTrustCAName());
        assertTrue(tCA1.equals(tCA2));
    }
    
    
    
    
}
