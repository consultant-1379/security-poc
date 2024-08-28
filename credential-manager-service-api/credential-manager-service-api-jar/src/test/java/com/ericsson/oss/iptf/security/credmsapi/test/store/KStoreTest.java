package com.ericsson.oss.iptf.security.credmsapi.test.store;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.TreeSet;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.ericsson.oss.iptf.security.credmsapi.test.utils.KeyAndCertUtil;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.StorageConstants;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.CredentialReaderFactory;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.CredentialWriterFactory;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.JKSReader;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.JKSWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.PKCS12Reader;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;

@RunWith(JUnit4.class)
public class KStoreTest {

    String signatureAlgorithmString = "SHA256WithRSAEncryption";
    //String certStoreName = "src/test/resources/admin-keystore";
    //String certPassword = "password";
    //String certAlias = "admin-cert";

    KeyAndCertUtil kSTestUtil = new KeyAndCertUtil();
    CredentialWriterFactory cwf = new CredentialWriterFactory();
    CredentialReaderFactory crf = new CredentialReaderFactory();

    final String keystorep12 = "/tmp/keystoreOnly.p12";
    final String truststorepkcs12 = "/tmp/truststorepkcs12.p12";
    final String keystorejks = "/tmp/keystore.jks";
    final String truststorejks = "/tmp/truststore.jks";

    final String jksFoldername = "/tmp/jksStore";
    final String pkcs12Foldername = "/tmp/pkcs12Store";
    final String keystorejceks = "/tmp/keystore.jceks";
    final String truststorejceks = "/tmp/truststore.jceks";
    final String jceksFoldername = "/tmp/jceksStore";
    final String alias = "pippo";

    @Before
    public void setup() {
        // prepareParameters();
        this.kSTestUtil.prepareParameters();
        //        this.kSTestUtil.prepareCert();
        //        this.kSTestUtil.prepareCAcert();
    }

    @Test
    public void testCredentialReader() {
        
        CredentialReaderFactory testCRF = new CredentialReaderFactory();
        CredentialReader crTest = null;
        String storeType = null;
        String storeFolderPath = null;
        String storeFilePath = null;
        String password = null;
        for(int i=0; i<8; i++) {
            switch(i) {
                case 1:
                    storeType = "";
                    break;
                case 2:
                    storeType = "wrongStoreType";
                    break;
                case 3:
                    storeFolderPath = "";
                    break;
                case 4:
                    storeFolderPath = null;
                    storeFilePath = "";
                    break;
                case 5:
                    storeFolderPath = "";
                    break;
                case 6:
                    storeFilePath = "storeFilePath";
                    break;
                case 7:
                    storeFilePath = "";
                    storeFolderPath = "storeFolderPath";
                    break;
            }
            try {
                crTest = testCRF.getCredentialreaderInstance(storeType, storeFolderPath, storeFilePath, password);
                assertTrue(false);
            } catch (StorageException e) {
                assertTrue(crTest == null);
            }
        }
        storeType = StorageConstants.JCEKS_STORE_TYPE;

        try {
            crTest = testCRF.getCredentialreaderInstance(storeType, storeFolderPath, storeFilePath, password);
            assertTrue(crTest instanceof JKSReader);
        } catch (StorageException e) {
            assertTrue(crTest instanceof JKSReader);
        }
    }
    
    @Test
    public void testCredentialWriter() {
        CredentialWriterFactory testCWF = new CredentialWriterFactory();
        CredentialWriter testcw = null;
        String storeType = null;
        String storeFolderPath = null;
        String storeFilePath = null;
        
        try {
            testcw = testCWF.getCredentialwriterInstanceForCRL(storeType, storeFolderPath, storeFilePath);
            assertTrue(false);
        } catch (StorageException e) {
            assertTrue(testcw == null);
        }
        for(int i=0;i<8;i++) {
            switch(i) {
                case 1:
                    storeType = "";
                    break;
                case 2:
                    storeType = "unsupportedStoreType";
                    break;
                case 3:
                    storeFolderPath = "";
                    break;
                case 4:
                    storeFolderPath = null;
                    storeFilePath = "";
                    break;
                case 5:
                    storeFolderPath = "";
                    break;
                case 6:
                    storeFilePath = "storeFilePath";
                    break;
                case 7:
                    storeFilePath = "";
                    storeFolderPath = "storeFolderPath";
                    break;             
            }
            try {
                testcw = testCWF.getCredentialwriterInstanceForTrust(storeType, storeFolderPath, storeFilePath);
                assertTrue(false);
            } catch (StorageException e) {
                assertTrue(testcw == null);
            }
        }
    }
    
    // PKCS12

    @Test
    public void testWritePKCS12KeyStore() {

        final File ksFile = new File(this.keystorep12);
        ksFile.delete();
        CredentialReader rPkcs = null;
        Certificate c = null;
        Certificate[] chain = new Certificate[2];
        Key k = null;

        // log.info(" Executing testWriteOnlyPKCS12Store ");
        //this.kSTestUtil.prepareCert();
        //assertTrue("Certificate was not read correctly", this.kSTestUtil.certChain.length != 0);

        //        final KeyPair keyPair = PrepareCertificate.createKeyPair();

        //        final KeyPair keyPair = this.kSTestUtil.keyPair;
        //        chain[0] = PrepareCertificate.prepareCertificate(keyPair);
        //        chain[1] = PrepareCertificate.prepareCertificate(keyPair);
        //        chain[0] = this.kSTestUtil.cert;
        //        chain[1] = this.kSTestUtil.cert;

        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForCert(StorageConstants.PKCS12_STORE_TYPE, this.keystorep12, "password");
            //chain = this.kSTestUtil.certChain;
            credWKS.storeKeyPair(this.kSTestUtil.certPrivateKey, this.kSTestUtil.certChain, this.alias);
            //            credWKS.storeKeyPair(keyPair.getPrivate(), this.kSTestUtil.certChain, this.alias);
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        assertTrue("KeyStore created", ksFile.exists());

        // test PKCS12 reader
        try {
            rPkcs = this.crf.getCredentialreaderInstance(StorageConstants.PKCS12_STORE_TYPE, this.keystorep12, "password");
            c = rPkcs.getCertificate(this.alias);
            chain = rPkcs.getCertificateChain(this.alias);
            k = rPkcs.getPrivateKey(this.alias);
        } catch (final StorageException e) {
            e.printStackTrace();
        }
        assertTrue("Certificate was not read correctly", c != null);
        assertTrue("Certificate chain was not read correctly", chain.length != 0);
        assertTrue("Private Key  was not read correctly", k != null);

        ksFile.delete();

    }

    @Test
    public void testWritePKCS12TrustStore() {

        // log.info(" Executing testWriteJKSTrustStore ");
        // prepareParameters();
        //this.kSTestUtil.prepareCAcert();
        assertTrue("CA chain was not created correctly", this.kSTestUtil.CaChain.length != 0);

        final File tsFile = new File(this.truststorepkcs12);
        tsFile.delete();
        CredentialWriter credWKS = null;
        CredentialReader credRKS = null;
        Certificate cert = null;
        try {
            credWKS = this.cwf.getCredentialwriterInstanceForTrust(StorageConstants.PKCS12_STORE_TYPE, this.truststorepkcs12, "password");
            cert = this.kSTestUtil.CaChain[1];
            //            final Certificate cert = this.kSTestUtil.cert;
            credWKS.addTrustedEntry(cert, this.alias);
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        assertTrue("TrustStore created", tsFile.exists());
        
        //Cannot read keystore/key/chain
        tsFile.setReadable(false, true);
        try {
            credRKS = this.crf.getCredentialreaderInstance(StorageConstants.PKCS12_STORE_TYPE, this.truststorepkcs12, "password");
            credRKS.getCertificate(this.alias);
            assertTrue(false);
        } catch (StorageException e2) {
            assertTrue(true);
        }
        try {
            credRKS.getPrivateKey(this.alias);
            assertTrue(false);
        } catch (StorageException e2) {
            assertTrue(true);
        }
        try {
            credRKS.getCertificateChain(this.alias);
            assertTrue(false);
        } catch (StorageException e2) {
            assertTrue(true);
        }
        
        tsFile.setReadable(true, true);

        //deleteEntry with different alias
        try {
            credWKS.deleteEntry("fakeAlias");
        } catch (StorageException e1) {
            assertTrue(false);
        }
        
        //cannot deleteEntry
        tsFile.setWritable(false, true);
        try {
            credWKS.deleteEntry("pippo");
        } catch (StorageException e1) {
            assertTrue(true);
        }
        
        assertTrue(tsFile.delete());
        
        //Cannot write bags case
        
        try {
            assertTrue(tsFile.createNewFile());
        } catch (IOException e) {
            assertTrue(false);
        }
        
        tsFile.setWritable(false, true);
        try {
            credWKS.addTrustedEntry(cert, this.alias);
        } catch (StorageException e) {
            assertTrue(true);
        }
        
        assertTrue(tsFile.delete());

    }

    @Test
    public void testWritePKCS12TrustFolder() {

        // log.info(" Executing testWriteJKSTrustFolder ");
        // prepareParameters();
        //this.kSTestUtil.prepareCAcert();
        assertTrue("CA chain was not created correctly", this.kSTestUtil.CaChain.length != 0);

        final File tsFolder = new File(this.pkcs12Foldername);
        tsFolder.mkdir();
        for (final File file : tsFolder.listFiles()) {
            file.delete();
        }
        
        CredentialWriter credWKS = null;
        try {
            credWKS = this.cwf.getCredentialwriterInstanceForTrust(StorageConstants.PKCS12_STORE_TYPE, this.pkcs12Foldername, "", "password");
            //            final Certificate cert = this.kSTestUtil.cert;

            credWKS.addTrustedEntry(this.kSTestUtil.CaChain[0], "cert1");
            credWKS.addTrustedEntry(this.kSTestUtil.CaChain[1], "cert2");
            //            credWKS.addTrustedEntry(cert, "cert1");
            //            credWKS.addTrustedEntry(cert, "cert2");
        } catch (final StorageException e) {
            assertTrue(false);
        }

        final File file1 = new File(this.pkcs12Foldername + File.separator + "cert1.p12");
        final File file2 = new File(this.pkcs12Foldername + File.separator + "cert2.p12");
        assertTrue("TrustFolder cert1 created", file1.exists());
        assertTrue("TrustFolder cert2 created", file2.exists());

        for (final File file : tsFolder.listFiles()) {
            file.delete();
        }
        tsFolder.delete();
        
        //write with not existent folder
        try {
            credWKS.addTrustedEntry(this.kSTestUtil.CaChain[1], "cert2");
        } catch (StorageException e) {
            assertTrue(false);
        }
        assertTrue("TrustFolder cert2 created", file2.exists());
        for (final File file : tsFolder.listFiles()) {
            file.delete();
        }
        tsFolder.delete();
    }

    // JKS

    @SuppressWarnings("static-access")
    @Test
    public void testWriteJKSKeyStore() {

        //this.kSTestUtil.prepareParameters();
        assertTrue("Certificate was not created correctly", this.kSTestUtil.cert != null);

        final File ksFile = new File(this.keystorejks);
        ksFile.delete();

        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForCert(StorageConstants.JKS_STORE_TYPE, this.keystorejks, "password");
            final Certificate[] chain = { this.kSTestUtil.cert };
            credWKS.storeKeyPair(this.kSTestUtil.keyPair.getPrivate(), chain, this.alias);
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        assertTrue("KeyStore created", ksFile.exists());
        // keystorep12.delete();

        // TEST ON CredentialReader

        CredentialReader credRKS = null;
        try {
            credRKS = this.crf.getCredentialreaderInstance(StorageConstants.JKS_STORE_TYPE, this.keystorejks, "password");
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        try {
            final Certificate c = credRKS.getCertificate(this.alias);
            assertTrue("reader cert ok", c != null);
            System.out.println(" Cert = " + c.getType().toString());
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        try {
            final Certificate[] c = credRKS.getCertificateChain(this.alias);
            assertTrue("reader chain ok", c.length != 0);
            System.out.println(" Cert = " + c.toString());
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        try {
            final Key k = credRKS.getPrivateKey(this.alias);
            assertTrue("reader key ok", k != null);
            System.out.println(" Cert = " + k.getFormat());
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        ksFile.delete();
    }

    @SuppressWarnings("static-access")
    @Test
    public void testWriteJKSTrustStore() {

        // log.info(" Executing testWriteJKSTrustStore ");
        // prepareParameters();
        //this.kSTestUtil.prepareCAcert();
        assertTrue("CA chain was not created correctly", this.kSTestUtil.CaChain.length != 0);

        final File tsFile = new File(this.truststorejks);
        tsFile.delete();

        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForTrust(StorageConstants.JKS_STORE_TYPE, this.truststorejks, "password");
            final Certificate cert = this.kSTestUtil.CaChain[1];
            credWKS.addTrustedEntry(cert, this.alias);
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        assertTrue("TrustStore created", tsFile.exists());

        Set<Certificate> certSet = new TreeSet<Certificate>();
        try {
            final CredentialReader credRKS = this.crf.getCredentialreaderInstance(StorageConstants.JKS_STORE_TYPE, this.truststorejks, "password");
            certSet = credRKS.getAllCertificates(this.alias);
        } catch (StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        assertTrue(certSet.size() == 1);
        tsFile.delete();
    }

    @SuppressWarnings("static-access")
    @Test
    public void testWriteJKSTrustFolder() {

        // log.info(" Executing testWriteJKSTrustFolder ");
        // prepareParameters();
        //this.kSTestUtil.prepareCAcert();
        assertTrue("CA chain was not created correctly", this.kSTestUtil.CaChain.length != 0);

        final File tsFolder = new File(this.jksFoldername);
        tsFolder.mkdir();
        for (final File file : tsFolder.listFiles()) {
            file.delete();
        }

        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForTrust(StorageConstants.JKS_STORE_TYPE, this.jksFoldername, "", "password");
            credWKS.addTrustedEntry(this.kSTestUtil.CaChain[0], "cert1");
            credWKS.addTrustedEntry(this.kSTestUtil.CaChain[1], "cert2");
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        final File file1 = new File(this.jksFoldername + File.separator + "cert1.jks");
        final File file2 = new File(this.jksFoldername + File.separator + "cert2.jks");
        assertTrue("TrustFolder cert1 created", file1.exists());
        assertTrue("TrustFolder cert2 created", file2.exists());

        for (final File file : tsFolder.listFiles()) {
            file.delete();
        }
        tsFolder.delete();
    }

    // JCEKS

    @SuppressWarnings("static-access")
    @Test
    public void testWriteJCEKSKeyStore() {

        //this.kSTestUtil.prepareParameters();
        assertTrue("Certificate was not created correctly", this.kSTestUtil.cert != null);

        final File ksFile = new File(this.keystorejceks);
        ksFile.delete();

        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForCert(StorageConstants.JCEKS_STORE_TYPE, this.keystorejceks, "password");
            final Certificate[] chain = { this.kSTestUtil.cert };
            credWKS.storeKeyPair(this.kSTestUtil.keyPair.getPrivate(), chain, this.alias);
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        assertTrue("KeyStore created", ksFile.exists());

        ksFile.delete();
    }

    @SuppressWarnings("static-access")
    @Test
    public void testWriteJCEKSTrustStore() {

        // log.info(" Executing testWriteJKSTrustStore ");
        // prepareParameters();
        //this.kSTestUtil.prepareCAcert();
        assertTrue("CA chain was not created correctly", this.kSTestUtil.CaChain.length != 0);

        final File tsFile = new File(this.truststorejceks);
        tsFile.delete();

        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForTrust(StorageConstants.JCEKS_STORE_TYPE, this.truststorejceks, "password");
            final Certificate cert = this.kSTestUtil.CaChain[1];
            credWKS.addTrustedEntry(cert, this.alias);
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        assertTrue("TrustStore created", tsFile.exists());

        tsFile.delete();
    }

    @SuppressWarnings("static-access")
    @Test
    public void testWriteJCEKSTrustFolder() {

        // log.info(" Executing testWriteJKSTrustFolder ");
        // prepareParameters();
        //this.kSTestUtil.prepareCAcert();
        assertTrue("CA chain was not created correctly", this.kSTestUtil.CaChain.length != 0);

        final File tsFolder = new File(this.jceksFoldername);
        tsFolder.mkdir();
        for (final File file : tsFolder.listFiles()) {
            file.delete();
        }

        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForTrust(StorageConstants.JCEKS_STORE_TYPE, this.jceksFoldername, "", "password");
            credWKS.addTrustedEntry(this.kSTestUtil.CaChain[0], "cert1");
            credWKS.addTrustedEntry(this.kSTestUtil.CaChain[1], "cert2");
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        final File file1 = new File(this.jceksFoldername + File.separator + "cert1.jceks");
        final File file2 = new File(this.jceksFoldername + File.separator + "cert2.jceks");
        assertTrue("TrustFolder cert1 created", file1.exists());
        assertTrue("TrustFolder cert2 created", file2.exists());

        for (final File file : tsFolder.listFiles()) {
            file.delete();
        }
        tsFolder.delete();
    }

    @Test
    public void testReaderJKSTrustStore() {

        // log.info(" Executing testWriteJKSTrustStore ");
        // prepareParameters();
        //this.kSTestUtil.prepareCAcert();
        assertTrue("CA chain was not created correctly", this.kSTestUtil.certChain.length != 0);

        final File tsFile = new File(this.truststorejks);
        tsFile.delete();

        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForTrust(StorageConstants.JKS_STORE_TYPE, this.truststorejks, "password");
            credWKS.addTrustedEntry(this.kSTestUtil.certChain[0], this.alias);
            credWKS.addTrustedEntry(this.kSTestUtil.certChain[1], "pippo1");
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        assertTrue("TrustStore created", tsFile.exists());
        CredentialReader credRKS = null;
        try {
            credRKS = this.crf.getCredentialreaderInstance(StorageConstants.JKS_STORE_TYPE, this.truststorejks, "password");
            final Set<Certificate> certs = credRKS.getAllCertificates("");
            for (final Certificate cert : certs) {
                final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                final InputStream inputStream = new ByteArrayInputStream(cert.getEncoded());
                final X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
            }
            assertEquals(2, certs.size());
        } catch (final StorageException | CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        tsFile.delete();
    }

    @Test
    public void testReaderJKSTrustStoreForASpecificAlias() {

        // log.info(" Executing testWriteJKSTrustStore ");
        // prepareParameters();
        this.kSTestUtil.prepareCAcert();
        assertTrue("CA chain was not created correctly", this.kSTestUtil.certChain.length != 0);

        final File tsFile = new File(this.truststorejks);
        tsFile.delete();

        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForTrust(StorageConstants.JKS_STORE_TYPE, this.truststorejks, "password");
            credWKS.addTrustedEntry(this.kSTestUtil.certChain[0], this.alias);
            credWKS.addTrustedEntry(this.kSTestUtil.certChain[1], "pippo1");
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        assertTrue("TrustStore created", tsFile.exists());
        CredentialReader credRKS = null;
        try {
            credRKS = this.crf.getCredentialreaderInstance(StorageConstants.JKS_STORE_TYPE, this.truststorejks, "password");
            final Set<Certificate> certs = credRKS.getAllCertificates("pippo1");
            for (final Certificate cert : certs) {
                final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                final InputStream inputStream = new ByteArrayInputStream(cert.getEncoded());
                final X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
            }
            assertEquals(1, certs.size());
        } catch (final StorageException | CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        tsFile.delete();
    }

    @Test
    public void testReaderJKSTrustStoreForASpecificRootAlias() {

        // log.info(" Executing testWriteJKSTrustStore ");
        // prepareParameters();
        this.kSTestUtil.prepareCAcert();
        assertTrue("CA chain was not created correctly", this.kSTestUtil.certChain.length != 0);

        final File tsFile = new File(this.truststorejks);
        tsFile.delete();

        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForTrust(StorageConstants.JKS_STORE_TYPE, this.truststorejks, "password");
            credWKS.addTrustedEntry(this.kSTestUtil.certChain[0], this.alias);
            credWKS.addTrustedEntry(this.kSTestUtil.certChain[1], "pippo1");
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        assertTrue("TrustStore created", tsFile.exists());
        CredentialReader credRKS = null;
        try {
            credRKS = this.crf.getCredentialreaderInstance(StorageConstants.JKS_STORE_TYPE, this.truststorejks, "password");
            final Set<Certificate> certs = credRKS.getAllCertificates("pippo");
            for (final Certificate cert : certs) {
                final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                final InputStream inputStream = new ByteArrayInputStream(cert.getEncoded());
                final X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
            }
            assertEquals(2, certs.size());
        } catch (final StorageException | CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        tsFile.delete();
    }

    //TODO: ho dei dubbi su come faccia a funzionare visto che mette + certificati con lo stesso alias (this.alias) 
    @Test
    public void testReaderPKCS12TrustStore() {

        final File tsFile = new File(this.truststorepkcs12);
        tsFile.delete();
        //this.kSTestUtil.prepareCAcert();
        //this.testWritePKCS12KeyStore();

        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForTrust(StorageConstants.PKCS12_STORE_TYPE, this.truststorepkcs12, "password");
            final Certificate cert = this.kSTestUtil.CaChain[1];
            credWKS.addTrustedEntry(cert, this.alias);
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        assertTrue("CA chain was not created correctly", this.kSTestUtil.certChain.length != 0);

        assertTrue("TrustStore created", tsFile.exists());
        CredentialReader credRKS = null;
        try {
            credRKS = this.crf.getCredentialreaderInstance(StorageConstants.PKCS12_STORE_TYPE, this.keystorep12, "password");

            final Set<Certificate> certs = credRKS.getAllCertificates("");
            for (final Certificate cert : certs) {
                final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                final InputStream inputStream = new ByteArrayInputStream(cert.getEncoded());
                final X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
                assertEquals("CN=ENM PKI Root CA", certificate.getIssuerX500Principal().toString());
            }
        } catch (final StorageException | CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        tsFile.delete();
    }

    //TODO: ho dei dubbi su come faccia a funzionare visto che mette + certificati con lo stesso alias (this.alias) 
    @Test
    public void testReaderPKCS12TrustStoreForASpecificAlias() {

        final File tsFile = new File(this.truststorepkcs12);
        tsFile.delete();
        //this.kSTestUtil.prepareCAcert();

        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForTrust(StorageConstants.PKCS12_STORE_TYPE, this.truststorepkcs12, "password");
            final Certificate cert = this.kSTestUtil.CaChain[1];
            credWKS.addTrustedEntry(cert, this.alias);
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        assertTrue("CA chain was not created correctly", this.kSTestUtil.certChain.length != 0);

        assertTrue("TrustStore created", tsFile.exists());

        CredentialReader credRKS = null;
        try {
            credRKS = this.crf.getCredentialreaderInstance(StorageConstants.PKCS12_STORE_TYPE, this.keystorep12, "password");

            final Set<Certificate> certs = credRKS.getAllCertificates(this.alias);
            for (final Certificate cert : certs) {
                final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                final InputStream inputStream = new ByteArrayInputStream(cert.getEncoded());
                final X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
                assertEquals("CN=ENM PKI Root CA", certificate.getIssuerX500Principal().toString());
            }
        } catch (final StorageException | CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        tsFile.delete();
    }
    
    @Test
    public void JKSWriterTestExceptions() {
        File dirTest = new File("/tmp/testJKSFolder");
        dirTest.mkdir();
        dirTest.setWritable(false,true);
        
        CredentialWriter jksW = new JKSWriter(dirTest.getAbsolutePath(),"","","wrongStorageType"); //default to JKS storeType
        try {
            jksW.addTrustedEntry(this.kSTestUtil.CaChain[0], "alias1");
            assertTrue(false);
        } catch (StorageException e) {
            assertTrue(true);
        }
        dirTest.setWritable(true,true);
        assertTrue(dirTest.delete());
        
        try {
            jksW.addCrlEntry(null, null); //return nothing
        } catch (StorageException e) {
        }
        assertTrue(true);
    }
    
    @Test
    public void JKSReaderTestException() {
        
        File dirTest = new File("/tmp/testJKSFolder");
        dirTest.mkdir();
        dirTest.setReadable(false,true);
        
        CredentialReader jksR = new JKSReader(dirTest .getAbsolutePath(),"","","wrongStorageType"); //default to JKS storeType
               
        try {
            jksR.getCertificate("alias");
            assertTrue(false);
        } catch (StorageException e) {
            //
        }
        try {
            jksR.getCertificateChain("alias");
            assertTrue(false);
        } catch (StorageException e) {
            //
        }

        dirTest.setReadable(true,true);
        File fakeJKS = new File(dirTest.getAbsolutePath() + "/fakeJKS");
        try {
            assertTrue(fakeJKS.createNewFile());
        } catch (IOException e1) {
            //
        }
        try {
            jksR.getAllCertificates("alias");
            assertTrue(false);
        } catch (StorageException e) {
            assertTrue(true);
        }
 
        assertTrue(fakeJKS.delete());
        
         try {
            jksR.getPrivateKey("alias");
            assertTrue(false);
        } catch (StorageException e) {
            assertTrue(true);
        }
         
        assertTrue(dirTest.delete());
    }
    
    @Test
    public void PKCS12ReaderWriterTestException() throws IOException {
        
        CredentialWriter credWKS = null;
        
        try {
            credWKS = this.cwf.getCredentialwriterInstanceForCert(StorageConstants.PKCS12_STORE_TYPE, this.keystorep12, "password");
            credWKS.addCrlEntry(null, null); //doNothing
        } catch (StorageException e) {
            assertTrue(false);
        }
        
        //PKCS12Reader constructor
        CredentialReader testCredRP12 = new PKCS12Reader(null,null,null,"");
        try {
            assertTrue(testCredRP12.getCRLs("alias") == null); //doNothing
        } catch (StorageException e) {
            assertTrue(false);
        } 
        
        File tsFile = new File(this.truststorepkcs12);
        assertTrue(tsFile.createNewFile());
        CredentialReader credRKS = new PKCS12Reader("",this.truststorepkcs12,"",StorageConstants.PKCS12_STORE_TYPE);
        //Exception (file content is not pkcs12)
        try {
            credRKS.getCertificate(this.alias);
        } catch (StorageException e2) {
            assertTrue(true);
        } 
        assertTrue(tsFile.delete());
        
        //getAllCertificates Exception
        File p12Dir = new File(this.pkcs12Foldername);
        p12Dir.mkdir();
        File fakeP12 = new File(this.pkcs12Foldername+"/fake.p12");
        fakeP12.createNewFile();
        credRKS = new PKCS12Reader(this.pkcs12Foldername,"","",StorageConstants.PKCS12_STORE_TYPE);
        try {
            credRKS.getAllCertificates(this.alias);
            assertTrue(false);
        } catch (StorageException e) {
            assertTrue(true);
        }
        assertTrue(fakeP12.delete());
        assertTrue(p12Dir.delete());
        
    }

}
