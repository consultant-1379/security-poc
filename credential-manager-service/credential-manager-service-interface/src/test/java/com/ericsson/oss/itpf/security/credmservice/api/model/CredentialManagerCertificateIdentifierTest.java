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
package com.ericsson.oss.itpf.security.credmservice.api.model;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;

public class CredentialManagerCertificateIdentifierTest {

    private final static CredentialManagerCertificateIdentifier cmciA = new CredentialManagerCertificateIdentifier(new X500Principal("CN=DukeSubject, OU=JavaSoft, O=Sun Microsystems, C=US"),
            new X500Principal("CN=DukeIssuer, OU=JavaSoft, O=Sun Microsystems, C=US"), new BigInteger("12345678901234567890"));
    private final static CredentialManagerCertificateIdentifier cmciASubjectLess = new CredentialManagerCertificateIdentifier(
            new X500Principal("CN=BukeSubject, OU=JavaSoft, O=Sun Microsystems, C=US"), new X500Principal("CN=DukeIssuer, OU=JavaSoft, O=Sun Microsystems, C=US"), new BigInteger(
                    "12345678901234567890"));
    private final static CredentialManagerCertificateIdentifier cmciAIssuerLess = new CredentialManagerCertificateIdentifier(
            new X500Principal("CN=DukeSubject, OU=JavaSoft, O=Sun Microsystems, C=US"), new X500Principal("CN=DukeIssuer, OU=JavaPoft, O=Sun Microsystems, C=US"), new BigInteger(
                    "12345678901234567890"));
    private final static CredentialManagerCertificateIdentifier cmciASNLess = new CredentialManagerCertificateIdentifier(new X500Principal("CN=DukeSubject, OU=JavaSoft, O=Sun Microsystems, C=US"),
            new X500Principal("CN=DukeIssuer, OU=JavaSoft, O=Sun Microsystems, C=US"), new BigInteger("12345678901234566890"));
    private final static CredentialManagerCertificateIdentifier cmciASubjectMajor = new CredentialManagerCertificateIdentifier(new X500Principal(
            "CN=SukeSubject, OU=JavaSoft, O=Sun Microsystems, C=US"), new X500Principal("CN=DukeIssuer, OU=JavaSoft, O=Sun Microsystems, C=US"), new BigInteger("12345678901234567890"));
    private final static CredentialManagerCertificateIdentifier cmciAIssuerMajor = new CredentialManagerCertificateIdentifier(
            new X500Principal("CN=DukeSubject, OU=JavaSoft, O=Sun Microsystems, C=US"), new X500Principal("CN=DukeIssuer, OU=JavbSoft, O=Sun Microsystems, C=US"), new BigInteger(
                    "12345678901234567890"));
    private final static CredentialManagerCertificateIdentifier cmciASNMajor = new CredentialManagerCertificateIdentifier(new X500Principal("CN=DukeSubject, OU=JavaSoft, O=Sun Microsystems, C=US"),
            new X500Principal("CN=DukeIssuer, OU=JavaSoft, O=Sun Microsystems, C=US"), new BigInteger("12345778901234567890"));
    private final static CredentialManagerCertificateIdentifier cmciAsubjectNull = new CredentialManagerCertificateIdentifier(null, new X500Principal(
            "CN=DukeIssuer, OU=JavaSoft, O=Sun Microsystems, C=US"), new BigInteger("12345678901234567890"));
    private final static CredentialManagerCertificateIdentifier cmciAissuerNull = new CredentialManagerCertificateIdentifier(
            new X500Principal("CN=DukeSubject, OU=JavaSoft, O=Sun Microsystems, C=US"), null, new BigInteger("12345678901234567890"));
    private final static CredentialManagerCertificateIdentifier cmciASNNull = new CredentialManagerCertificateIdentifier(new X500Principal("CN=DukeSubject, OU=JavaSoft, O=Sun Microsystems, C=US"),
            new X500Principal("CN=DukeIssuer, OU=JavaSoft, O=Sun Microsystems, C=US"), null);

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateIdentifier#compareTo(com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateIdentifier)}
     * .
     */
    @Test
    public void testCompareToIdentity() {
        assertTrue(cmciA.compareTo(cmciA) == 0);
    }

    @Test
    public void testCompareToLesser() {
        assertTrue(cmciASubjectLess.compareTo(cmciA) < 0);
        assertTrue(cmciAIssuerLess.compareTo(cmciA) < 0);
        assertTrue(cmciASNLess.compareTo(cmciA) < 0);
    }

    @Test
    public void testCompareToMajor() {
        assertTrue(cmciASubjectMajor.compareTo(cmciA) > 0);
        assertTrue(cmciAIssuerMajor.compareTo(cmciA) > 0);
        assertTrue(cmciASNMajor.compareTo(cmciA) > 0);
    }

    @Test
    public void testCompareNullToNull() {
        final CredentialManagerCertificateIdentifier a = new CredentialManagerCertificateIdentifier();
        final CredentialManagerCertificateIdentifier b = new CredentialManagerCertificateIdentifier();

        assertTrue(a.compareTo(b) == 0);

    }

    @Test
    public void testCompareToNull() {
        assertTrue(cmciA.compareTo(cmciAsubjectNull) > 0);
        assertTrue(cmciA.compareTo(cmciAissuerNull) > 0);
        assertTrue(cmciA.compareTo(cmciASNNull) > 0);
        assertTrue(cmciAsubjectNull.compareTo(cmciA) < 0);
        assertTrue(cmciAissuerNull.compareTo(cmciA) < 0);
        assertTrue(cmciASNNull.compareTo(cmciA) < 0);
    }
}
