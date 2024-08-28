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
package com.ericsson.oss.itpf.security.credmservice.util;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateAuthority;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerStartupException;
import com.ericsson.oss.itpf.security.credmservice.test.TestHelper;

public class CredMJKSWriterTest {

    private static String JKSFILEPATH = "/tmp/testCredMJKSWriterTest.jks";
    private static String PASSWORD = "duck";

    private static final String KEYALGY = "RSA";
    private static final String EXTCA_SIGALG = "SHA256withRSA";
    private static final int KEYSIZE = 1024;

    public static final String EXT_CA_NAME_1 = "extCAnumber1";
    public static final String DN_1 = "CN=donald_1";

    private boolean initialized = false;

    private KeyPair keyPair1;
    private X500Name x500Name;
    private X509Certificate cert1;

    @Before
    public synchronized void setup() {
        if (!initialized) {
            try {
                initialized = true;
                keyPair1 = TestHelper.generateKeyPair(KEYALGY, KEYSIZE);

                x500Name = new X500Name(DN_1);
                cert1 = TestHelper.issueSelfSignedCertificate(keyPair1, x500Name, EXTCA_SIGALG);
            } catch (final NoSuchAlgorithmException e) {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testStoreKeyPair() {

        try {
            final PrintWriter writer = new PrintWriter(JKSFILEPATH, "UTF-8");
            writer.println("The first line");
            writer.close();

            final CredMJKSWriter jksWriter = new CredMJKSWriter(JKSFILEPATH, PASSWORD);

            final Certificate chain[] = new Certificate[1];
            chain[0] = cert1;

            jksWriter.storeKeyPair(keyPair1.getPrivate(), cert1, "donaldAlias", chain);
        } catch (final CredentialManagerStartupException | FileNotFoundException | UnsupportedEncodingException e) {
            assertTrue(false);
        }
        
        JKSReader jksReader = null;
        
        jksReader = new JKSReader(JKSFILEPATH, PASSWORD, "JKS");
        Certificate jksCert  = null;
        
        KeyStore ksTest = null;
        Method method = null;
        try {
            method = JKSReader.class.getDeclaredMethod("getKeyStore");
            method.setAccessible(true);
            ksTest = (KeyStore)method.invoke(jksReader);
        } catch (final Exception e2) {
            assertTrue(false);
        }
        
        jksCert = jksReader.getCertificate("donaldAlias");
        System.out.println(jksCert.getType());
        assertTrue(jksCert.getType().equals("X.509") && jksCert.getPublicKey().equals(keyPair1.getPublic()));
        assertTrue(jksReader.isAliasPresent("donaldAlias"));
        assertTrue(jksCert.equals(jksReader.getAllCertificates().get(0)));
    }

    @Test
    public void testaddTrustEntries() {

        try {
            final PrintWriter writer = new PrintWriter(JKSFILEPATH, "UTF-8");
            writer.println("The first line");
            writer.close();

            final CredMJKSWriter jksWriter = new CredMJKSWriter(JKSFILEPATH, PASSWORD);

            final Certificate chain[] = new Certificate[1];
            chain[0] = cert1;

            final CredentialManagerCertificateAuthority certAuthInt = new CredentialManagerCertificateAuthority("pippoInt");
            certAuthInt.add(cert1);
            final Map<String, CredentialManagerCertificateAuthority> intCA = new HashMap<String, CredentialManagerCertificateAuthority>();
            intCA.put("pippoInt", certAuthInt);
            final CredentialManagerCertificateAuthority certAuthExt = new CredentialManagerCertificateAuthority("pippoExt");
            certAuthInt.add(cert1);
            final Map<String, CredentialManagerCertificateAuthority> extCA = new HashMap<String, CredentialManagerCertificateAuthority>();
            extCA.put("pippoExt", certAuthExt);

            jksWriter.addTrustedEntries(intCA, extCA, "goofy");
        } catch (final CredentialManagerStartupException | FileNotFoundException | UnsupportedEncodingException | CertificateEncodingException e) {
            assertTrue(false);
        }
    }

    @Test
    public void testaddTrustEmptyEntries() throws CertificateEncodingException {

        try {
            final PrintWriter writer = new PrintWriter(JKSFILEPATH, "UTF-8");
            writer.println("The first line");
            writer.close();

            final CredMJKSWriter jksWriter = new CredMJKSWriter(JKSFILEPATH, PASSWORD);

            final Certificate chain[] = new Certificate[1];
            chain[0] = cert1;

            final Map<String, CredentialManagerCertificateAuthority> intCA = new HashMap<String, CredentialManagerCertificateAuthority>();
            final Map<String, CredentialManagerCertificateAuthority> extCA = new HashMap<String, CredentialManagerCertificateAuthority>();

            jksWriter.addTrustedEntries(intCA, extCA, "goofy");
        } catch (final CredentialManagerStartupException | FileNotFoundException | UnsupportedEncodingException e) {
            assertTrue(false);
        }
    }

    @Test
    public void testStoreFail() throws IOException {
        
        File jksFile = new File(JKSFILEPATH); 
        CredMJKSWriter jksWriter = null;
        
        try {
            jksWriter = new CredMJKSWriter(JKSFILEPATH, PASSWORD);
        } catch (CredentialManagerStartupException e) {
            assertTrue(false);
        }
        
        final Certificate chain[] = new Certificate[1];
        chain[0] = cert1;
        assertTrue(jksFile.createNewFile());
        jksFile.setWritable(false, true);
        try {
            jksWriter.storeKeyPair(keyPair1.getPrivate(), cert1, "donaldAlias", chain);
            assertTrue(false);
        } catch (CredentialManagerStartupException e) {
            assertTrue(true);
        }
        try {
            jksWriter.addTrustedEntries(null, null, "donaldAlias");;
            assertTrue(false);
        } catch (CredentialManagerStartupException e) {
            assertTrue(true);
        }
        jksFile.setWritable(true, true);        
    }
    
    @Test
    public void testPrivJKSReaderConstructor() throws NoSuchMethodException, SecurityException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, FileNotFoundException {
        Constructor<JKSReader> constructor;
        constructor = JKSReader.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        JKSReader jksread = constructor.newInstance();
        assertTrue(jksread != null);
        assertTrue(jksread.isAliasPresent("alias") == false);
        assertTrue(jksread.getCertificate("alias") == null);
        assertTrue(jksread.getAllCertificates().isEmpty());
        
        //uncapable to found the ks file. Nonetheless it will create the keystore instance
        try {
            Method method = JKSReader.class.getDeclaredMethod("getKeyStore");
            method.setAccessible(true);
            KeyStore ksTest = (KeyStore)method.invoke(jksread);
            assertTrue(ksTest != null);
        } catch (final Exception e2) {
            assertTrue(false);
        }

        final Certificate chain[] = new Certificate[1];
        chain[0] = cert1;
        try {
            CredMJKSWriter jksWriter = new CredMJKSWriter(JKSFILEPATH, PASSWORD);
            jksWriter.storeKeyPair(keyPair1.getPrivate(), cert1, "donaldAlias", chain);
        } catch (CredentialManagerStartupException e) {
            assertTrue(false);
        }
        
        //Constructor with InputStream
        InputStream inStream = new FileInputStream(JKSFILEPATH);
        JKSReader jksIS = new JKSReader(inStream, PASSWORD, "JKS");
        //keystore member field already filled
        try {
            Method method = JKSReader.class.getDeclaredMethod("getKeyStore");
            method.setAccessible(true);
            KeyStore ksTest = (KeyStore)method.invoke(jksIS);
            assertTrue(ksTest != null);
        } catch (final Exception e2) {
            assertTrue(false);
        }
        //Constructor fail to read
        JKSReader jksFail = new JKSReader(inStream, "wrongPass", "JKS");
    }

    
    @After
    public void clean() {
        try {
            Files.deleteIfExists(Paths.get(JKSFILEPATH));
        } catch (final IOException e) {
            assertTrue(false);
        }
    }

}
