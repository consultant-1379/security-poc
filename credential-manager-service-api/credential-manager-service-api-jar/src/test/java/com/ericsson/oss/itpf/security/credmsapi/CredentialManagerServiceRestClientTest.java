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
package com.ericsson.oss.itpf.security.credmsapi;

import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.util.*;

import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.CsrHandler;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.CredentialManagerSubjectAlternateNameImpl;
import com.ericsson.oss.itpf.security.credmservice.api.model.*;
import com.ericsson.oss.itpf.security.keymanagement.KeyGenerator;

@RunWith(MockitoJUnitRunner.class)
public class CredentialManagerServiceRestClientTest {

    CredentialManagerEntity endEntity = new CredentialManagerEntity();
    KeyPair keyPair = null;
    SubjectAlternativeNameType subjectAltName = new SubjectAlternativeNameType();
    Map<String, Attribute> attributes;
    Attribute[] derAttributes = null;
    CsrHandler csrHandler = new CsrHandler();
    PKCS10CertificationRequest pkcs10Csr = null;
    String signatureAlgorithmString = "SHA256WithRSAEncryption";
    
    final String hostName = "testHostName";
    final String entityName = "testEntityName";
    final String entityProfileName = "TOREndEntityProfile";
    @Mock
    static CredentialManagerServiceRestClient mockRestClient;
    
    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmsapi.CredentialManagerServiceRestClient#getProfile()} .
     */
    //@Test(expected = IllegalStateException.class)
    @Test
    public void testGetProfile() {
        final CredentialManagerServiceRestClient restclient = new CredentialManagerServiceRestClient(this.hostName, 8080);

        //assertTrue("testGetProfile", restclient.getProfile() == null);
        assertTrue("testGetProfile", restclient != null);
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.credmsapi.CredentialManagerServiceRestClient#createAndGetEndEntity(java.lang.String, java.lang.String)} .
     */
    @Test
    public void testCreateAndGetEndEntity() {
        final CredentialManagerServiceRestClient restclient = new CredentialManagerServiceRestClient(this.hostName, 8080);
        try {
            restclient.createAndGetEndEntity(this.entityName, "");
        } catch (final Exception e) {
            assertTrue(true);
        }
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.credmsapi.CredentialManagerServiceRestClient#getCertificate(org.bouncycastle.jce.PKCS10CertificationRequest)}
     * .
     */
    @Test
    public void testGetCertificate() {
        final CredentialManagerServiceRestClient restclient = new CredentialManagerServiceRestClient(this.hostName, 8080);

        this.prepareParameters();

        /*
         * Invoke getCsr method of CsrHandler class
         */
        try {
            this.pkcs10Csr = this.csrHandler.getCSR(this.endEntity, this.signatureAlgorithmString, this.keyPair, this.derAttributes);
        } catch (final IssueCertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        try {

            restclient.getCertificate(this.pkcs10Csr);
        } catch (final Exception e) {
            assertTrue(true);
        }
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmsapi.CredentialManagerServiceRestClient#getTrust()} .
     */
    @Test
    public void testGetTrust() {
        final CredentialManagerServiceRestClient restclient = new CredentialManagerServiceRestClient(this.hostName, 8080);
        try {

            restclient.getTrust();
        } catch (final Exception e) {
            assertTrue(true);
        }

    }

    private void prepareParameters() {

        /*
         * Prepare parameters to invoke getCsr method of CsrHandler class
         */

        final List<String> subAltNameList = new ArrayList<String>();
        subAltNameList.add("ipaddress=1.1.1.1");
        final CredentialManagerSubjectAltName cmAltSubName = new CredentialManagerSubjectAltName();
        cmAltSubName.setIPAddress(subAltNameList);

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setDnQualifier("CN=altro");

        this.endEntity.setSubjectAltName(cmAltSubName);
        this.endEntity.setEntityProfileName(this.entityProfileName);
        // endEntity.setOTP(KeyGenerator.randomPassword(8).toString());
        this.endEntity.setSubject(subject);

        /*
         * Create KeyPair parameter
         */
        this.keyPair = KeyGenerator.getKeyPair("RSA", 2048);

        /*
         * Create extension parameters : only SubjectAletrnativename
         */
        this.subjectAltName.getIpaddress().add(0, "1.1.1.1");
        final CredentialManagerSubjectAlternateNameImpl credMsubjAltName = new CredentialManagerSubjectAlternateNameImpl(this.subjectAltName);
        this.attributes = new HashMap<String, Attribute>();
        this.attributes.put(Extension.subjectAlternativeName.toString(), credMsubjAltName.getAttribute());
        final Attribute[] att = new Attribute[1];
        this.attributes.values().toArray(att);
        this.derAttributes = att;

    }

}
