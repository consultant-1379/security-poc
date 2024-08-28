package com.ericsson.oss.itpf.security.credmsapi.business.handlers;

import static org.junit.Assert.assertTrue;

import java.security.KeyPair;

import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;

import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtensionImpl;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.PrepareCertificate;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerBasicConstraints;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateExtensions;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerExtendedKeyUsage;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerKeyUsage;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;

public class CsrHandlerTest {

    @Test
    public void getCsrTest() throws IssueCertificateException {
        CsrHandler handler = new CsrHandler();
        PKCS10CertificationRequest csr = null;
        try {
            csr = handler.getCSR(new CredentialManagerEntity(), "md5", new KeyPair(null, null), null);
            assertTrue(false);
        } catch (IssueCertificateException e) {
            assertTrue(csr == null);
        }
        
        KeyPair kp = PrepareCertificate.createKeyPair();
        final CSRAttributesHandler csrAttributesHandler = new CSRAttributesHandler();
        Attribute[] attributes = null;
        CredentialManagerProfileInfo profileInfo = new CredentialManagerProfileInfo();
        CredentialManagerCertificateExtensionImpl xmlextension = new CredentialManagerCertificateExtensionImpl();
        xmlextension.setSubjectAlternativeName("");
        attributes = csrAttributesHandler.generateAttributes(profileInfo, xmlextension);
        CredentialManagerEntity entity = new CredentialManagerEntity();
        CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setCommonName("cn");
        entity.setSubject(subject);
        
        try {
            csr = handler.getCSR(entity, "MD5WITHRSA", kp, attributes);
            assertTrue(csr != null);
        } catch (IssueCertificateException e)
        {
            assertTrue(false);
        }
    }
    
    @Test
    public void testGetCsrEmptyFields() {
        CsrHandler handler = new CsrHandler();
        KeyPair kp = PrepareCertificate.createKeyPair();
        final CSRAttributesHandler csrAttributesHandler = new CSRAttributesHandler();
        Attribute[] attributes = null;
        CredentialManagerProfileInfo profileInfo = new CredentialManagerProfileInfo();
        CredentialManagerCertificateExtensionImpl xmlextension = new CredentialManagerCertificateExtensionImpl();
        CredentialManagerCertificateExtensions extAttrs = new CredentialManagerCertificateExtensions();
        //BasicConstraints
        CredentialManagerBasicConstraints cmBC = new CredentialManagerBasicConstraints();
        cmBC.setEnabled(false);
        extAttrs.setBasicConstraints(cmBC);
        //KeyUsage
        CredentialManagerKeyUsage cmKU = new CredentialManagerKeyUsage();
        extAttrs.setKeyUsage(cmKU);
        //ExtendedKeyUsage
        CredentialManagerExtendedKeyUsage cmEKU = new CredentialManagerExtendedKeyUsage();
        extAttrs.setExtendedKeyUsage(cmEKU);
        profileInfo.setExtentionAttributes(extAttrs);
        //just for coverage (these classes have only static methods)
        CSRAttributesSubAltNameHandler unusedSANH= new CSRAttributesSubAltNameHandler();
        assertTrue(unusedSANH != null);
        CSRAttributesBasicConstraintsHandler unusedBCH= new CSRAttributesBasicConstraintsHandler();
        assertTrue(unusedBCH != null);
        CSRAttributesKeyUsageHandler unusedKUH= new CSRAttributesKeyUsageHandler();
        assertTrue(unusedKUH != null);
        CSRAttributesExtendedKeyUsageHandler unusedEKUH= new CSRAttributesExtendedKeyUsageHandler();
        assertTrue(unusedEKUH != null);
        CSRAttributesSubjectKeyIdentifierHandler unusedSKIH= new CSRAttributesSubjectKeyIdentifierHandler();
        assertTrue(unusedSKIH != null);
        
                
        attributes = csrAttributesHandler.generateAttributes(profileInfo, xmlextension);
        
        CredentialManagerEntity entity = new CredentialManagerEntity();
        CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setCommonName("cn");
        entity.setSubject(subject); 
        try {
            PKCS10CertificationRequest csr = handler.getCSR(entity, "MD5WITHRSA", kp, attributes);
            assertTrue(csr != null);
        } catch (IssueCertificateException e)
        {
            assertTrue(false);
        }
    }
    
}
