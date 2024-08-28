package com.ericsson.oss.iptf.security.credmsapi.test.store;

import static org.junit.Assert.assertTrue;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.ericsson.oss.iptf.security.credmsapi.test.utils.KeyAndCertUtil;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.PrepareCertificate;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.StorageConstants;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.*;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCrlMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509CRL;

@RunWith(JUnit4.class)
public class Base64StoreTest {

    KeyAndCertUtil kSTestUtil = new KeyAndCertUtil();

    CredentialWriterFactory cwf = new CredentialWriterFactory();
    // Logger log = LoggerFactory.getLogger(KStoreTest.class);

    KeyStore certKeystore;
    //final String certStoreName = "src/test/resources/admin-keystore";
    //final String certPassword = "password";
    //final String certAlias = "admin-cert";

    final String ksFilename = "/tmp/base64keystore.pem";
    final String keyFilename = "/tmp/base64key.key";
    final String certFilename = "/tmp/base64cert.cer";
    final String tsFilename = "/tmp/base64TrustStore.pem";
    final String tsFoldername = "/tmp/b64store";

    //  TODO
    // using a password with "AES-256-CFB" encryption algorithm Maven fails to perform the test
    // it seems not find the correct library or the JVM doent support an high cyper mode
    // org.bouncycastle.openssl.encryptionexception: exception using cipher - please check password and data.
    // Caused by: java.security.InvalidKeyException: Illegal key size
    final String base64Password = "pippo";

    @Before
    public void setup() {
        // prepareParameters();
        this.kSTestUtil.prepareParameters();
        //        this.kSTestUtil.prepareCert();
        //        this.kSTestUtil.prepareCAcert();
    }

    @Test
    public void testPrivConstructor() throws NoSuchMethodException, SecurityException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, StorageException {
        Constructor<Base64Reader> constructor;
        constructor = Base64Reader.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        Base64Reader b64read = constructor.newInstance();
        assertTrue(b64read != null);
        
        //Null entries (however they are atleast set empty)
        Base64Reader b64null = new Base64Reader(null,null,null,null,null);
        assertTrue(b64null.getCertificate("alias") == null); //does not trigger NullPointers
    }
    
    @Test
    public void testBase64WriterWrong() {
        try {
            Base64Writer b64wr = new Base64Writer(null,null,null,null,null);
            assertTrue(b64wr != null);
            Certificate[] certificateChain = {};
            KeyPair kp = PrepareCertificate.createKeyPair();
            b64wr.storeKeyPair(kp.getPrivate(), certificateChain , null);
        } catch (StorageException e) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testBase64SingleKeyStore() {

        // log.info(" Executing testBase64SingleKeyStore ");
        //this.kSTestUtil.prepareCert();
        assertTrue("Certificate was not read correctly", this.kSTestUtil.certChain.length != 0);

        final File ksFile = new File(this.ksFilename);
        ksFile.delete();
        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForCert(StorageConstants.BASE64_PEM_STORE_TYPE, this.ksFilename, this.base64Password);
            credWKS.storeKeyPair(this.kSTestUtil.certPrivateKey, this.kSTestUtil.certChain, "alias");
            System.out.println("Init Key : " + this.getHexString(this.kSTestUtil.certPrivateKey.getEncoded()));
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        assertTrue("KeyStore created", ksFile.exists());
        //ksFile.delete();

        // TEMP !!!!!!!!!!!!!!!!!!!!!
        // TEST SU READER

        final Base64Reader br = new Base64Reader("", this.ksFilename, "", "", this.base64Password);
        Key myKey = null;
        try {
            myKey = br.getPrivateKey("alias");
            System.out.println("Read Key : " + this.getHexString(myKey.getEncoded()));
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        assertTrue("Key read", myKey != null);

        Certificate myCert = null;
        try {
            myCert = br.getCertificate("alias");
            System.out.println("cert : " + myCert.getType());
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        assertTrue("Certificate read", myCert != null);
        ksFile.delete();
    }

    @Test
    public void testBase64doulbleKeyStore() {

        // log.info(" Executing testBase64doulbleKeyStore ");
        //this.kSTestUtil.prepareCert();
        assertTrue("Certificate was not read correctly", this.kSTestUtil.certChain.length != 0);

        final File certFile = new File(this.certFilename);
        final File keyFile = new File(this.keyFilename);
        certFile.delete();
        keyFile.delete();
        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForCert(StorageConstants.BASE64_PEM_STORE_TYPE, "", this.certFilename, this.keyFilename, this.base64Password);
            credWKS.storeKeyPair(this.kSTestUtil.certPrivateKey, this.kSTestUtil.certChain, "alias");
            System.out.println("Init Key : " + this.getHexString(this.kSTestUtil.certPrivateKey.getEncoded()));
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        assertTrue("Certificate file created", certFile.exists());
        //certFile.delete();
        assertTrue("Private key file created", keyFile.exists());
        //keyFile.delete();

        // TEST ON READER

        Base64Reader br = new Base64Reader("", this.keyFilename, "", "", this.base64Password);
        Key myKey = null;
        try {
            myKey = br.getPrivateKey("alias");
            System.out.println("Read Key : " + this.getHexString(myKey.getEncoded()));
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        assertTrue("Certificare read", myKey != null);

        br = new Base64Reader("", this.certFilename, "", "", this.base64Password);
        Certificate myCert = null;
        try {
            myCert = br.getCertificate("alias");
            System.out.println("cert : " + myCert.getType());
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        assertTrue("Certificate read", myCert != null);
        certFile.delete();
        keyFile.delete();
    }

    @Test
    public void testWriteBase64TrustStore() throws IOException {

        // log.info(" Executing testWriteBase64TrustStore ");
        // prepareParameters();
        //this.kSTestUtil.prepareCAcert();
        assertTrue("CA chain was not created correctly", this.kSTestUtil.CaChain.length != 0);

        final File tsFile = new File(this.tsFilename);
        tsFile.delete();
        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForTrust(StorageConstants.BASE64_PEM_STORE_TYPE, this.tsFilename, "");
            final Certificate cert = this.kSTestUtil.CaChain[1];
            credWKS.addTrustedEntry(cert, "alias");
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        assertTrue("TrustStore created", tsFile.exists());
        assertTrue(tsFile.delete());
        
        //addTrustedEntryException on write
        tsFile.createNewFile();
        tsFile.setWritable(false, true);
        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForTrust(StorageConstants.BASE64_PEM_STORE_TYPE, this.tsFilename, "");
            final Certificate cert = this.kSTestUtil.CaChain[1];
            credWKS.addTrustedEntry(cert, "alias");
            assertTrue(false);
        } catch (final StorageException e) {
            assertTrue(true);
        }
        assertTrue(!tsFile.delete()); //should have been deleted by addTrustedEntry
    }

    @Test
    public void testWriteBase64TrustFolder() {

        // log.info(" Executing testWriteBase64TrustFolder ");
        // prepareParameters();
        //this.kSTestUtil.prepareCAcert();
        assertTrue("CA chain was not created correctly", this.kSTestUtil.CaChain.length != 0);

        final File tsFolder = new File(this.tsFoldername);
        tsFolder.mkdir();
        for (final File file : tsFolder.listFiles()) {
            file.delete();
        }

        try {
            final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForTrust(StorageConstants.BASE64_PEM_STORE_TYPE, this.tsFoldername, "", "");
            credWKS.addTrustedEntry(this.kSTestUtil.CaChain[0], "cert1");
            credWKS.addTrustedEntry(this.kSTestUtil.CaChain[1], "cert2");
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        final File file1 = new File(this.tsFoldername + File.separator + "cert1.pem");
        final File file2 = new File(this.tsFoldername + File.separator + "cert2.pem");
        assertTrue("TrustFolder cert1 created", file1.exists());
        assertTrue("TrustFolder cert2 created", file2.exists());
        //tsFile.delete();

        // TEST ON READER

        final Base64Reader br = new Base64Reader(this.tsFoldername, "", "", "", this.base64Password);
        Certificate[] myCert = null;
        try {
            myCert = br.getCertificateChain("alias");
            System.out.println("trust chain " + myCert.length);
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        assertTrue("Certificate chain read", myCert != null);

        for (final File file : tsFolder.listFiles()) {
            file.delete();
        }
        tsFolder.delete();
    }
    
    @Test
    public void testWriteCertKeyDifferentFiles() {
        File ksFile = new File("/tmp/getAllCerts64Full.crt");
        File keyFile = new File("/tmp/getAllCerts64Full.key");
        KeyPair kp = PrepareCertificate.createKeyPair();
        try {
            CredentialWriter credWKS = new Base64Writer("","",ksFile.getAbsolutePath(),keyFile.getAbsolutePath(), "");
            X509Certificate x509Cert = PrepareCertificate.prepareCertificate(kp);
            Certificate[] certArray = { x509Cert };
            credWKS.storeKeyPair(kp.getPrivate(), certArray , "alias");
        } catch (StorageException e) {
            assertTrue(false);
        }
        assertTrue("KeyStore and KeyFile created", ksFile.exists() && keyFile.exists());
        
        try {
            CredentialReader credRKS = new Base64Reader("","",ksFile.getAbsolutePath(),keyFile.getAbsolutePath(), "");
            Certificate cert = credRKS.getCertificate("alias");
            Key prKey = credRKS.getPrivateKey("alias");
            ksFile.delete();
            keyFile.delete();
            assertTrue(cert.getPublicKey().equals(kp.getPublic()) && prKey.equals(kp.getPrivate()));
        } catch (StorageException e) {
            ksFile.delete();
            keyFile.delete();
            assertTrue(false);
        }
        //Files not existent
        try {
            CredentialReader credRKS2 = new Base64Reader("","",ksFile.getAbsolutePath(),keyFile.getAbsolutePath(), "");
            Certificate cert2 = credRKS2.getCertificate("alias");
            Key prKey2 = credRKS2.getPrivateKey("alias");
            assertTrue(cert2 == null && prKey2 == null);
        } catch (StorageException e) {
            assertTrue(false);
        }
    }

    @Test
    public void testWriteBase64CrlFolder() {
        try {

            final CredentialManagerCrlMaps crlMap = PrepareCertificate.generateInternalCrl();

            X509CRL x509Crl = null;
            final Collection<CredentialManagerX509CRL> coll = crlMap.getInternalCACrlMap().values();
            final Iterator<CredentialManagerX509CRL> iter = coll.iterator();
            while (iter.hasNext()) {
                x509Crl = iter.next().retrieveCRL();
                break;
            }

            final File tsFolder = new File(this.tsFoldername);
            tsFolder.mkdir();
            for (final File file : tsFolder.listFiles()) {
                file.delete();
            }
            try {
                final CredentialWriter credWKS = this.cwf.getCredentialwriterInstanceForTrust(StorageConstants.BASE64_PEM_STORE_TYPE, this.tsFoldername, "", "");
                credWKS.addCrlEntry(x509Crl, "cert1");
            } catch (final StorageException e) {
                assertTrue("Exception not expected", false);
            }

            // Direct test on write file with password
            File crlfile = new File("/tmp/mycrl.pem");
            crlfile.delete();
            Base64Writer b64w = new Base64Writer("", "/tmp/mycrl.pem", "", "", this.base64Password);
            b64w.addCrlEntry(x509Crl, "alias");
            assertTrue("Write CRL", crlfile.exists());
            CredentialReader b64reader = new Base64Reader(this.tsFoldername,"","","","");
            assertTrue(b64reader.getCRLs("alias").size() == 0);
            assertTrue(crlfile.delete());
            
            b64reader = new Base64Reader("/tmp/notexistantfolder","","","","");
            assertTrue(b64reader.getCRLs("alias").size() == 0);
            
            crlfile = new File("/tmp/mycrl.pem");
            crlfile.createNewFile();
            b64w = new Base64Writer("", "/tmp/mycrl.pem", "", "", this.base64Password);
            b64w.addCrlEntry(x509Crl, "alias");
            assertTrue("Write CRL", crlfile.exists());
            b64reader = new Base64Reader("/tmp/mycrl.pem","","","","");
            assertTrue(b64reader.getCRLs("alias").size() == 0);
            assertTrue(crlfile.delete());
            
            crlfile = new File(this.tsFoldername+"/mycrl1.pem");
            assertTrue(crlfile.createNewFile());
            b64w = new Base64Writer("", this.tsFoldername+"/mycrl.pem", "", "", "");
            b64w.addCrlEntry(x509Crl, "alias");
            assertTrue("Write CRL", crlfile.exists());
            b64reader = new Base64Reader(this.tsFoldername,"","","","");
            assertTrue(b64reader.getCRLs("").size() == 0);
            assertTrue(crlfile.delete());
            
            crlfile = new File(this.tsFoldername+"/mycrl.pem");
            b64w = new Base64Writer("", this.tsFoldername+"/mycrl.pem", "", "", "");
            b64w.addCrlEntry(x509Crl, "alias");
            assertTrue("Write CRL", crlfile.exists());
            b64reader = new Base64Reader(this.tsFoldername,"","","","");
            assertTrue(b64reader.getCRLs(null).size() == 0);
            crlfile.delete();
            
            crlfile = new File(this.tsFoldername+"/mycrl.pem");
            b64w = new Base64Writer("", this.tsFoldername+"/mycrl.pem", "", "", "");
            b64w.addCrlEntry(x509Crl, "mycrl");
            assertTrue("Write CRL", crlfile.exists());
            b64reader = new Base64Reader(this.tsFoldername,"","","","");
            assertTrue(b64reader.getCRLs("mycrl").size() == 1);
            crlfile.delete();

            for (final File file : tsFolder.listFiles()) {
                file.delete();
            }
            tsFolder.delete();

        } catch (final StorageException | IOException e) {
            assertTrue("Exception not expected", false);
        }
    }
    
    @Test
    public void testgetAllCertificates() {
        CredentialReader b64reader = new Base64Reader("",this.ksFilename,"","","");
        try {
            assertTrue(b64reader.getAllCertificates("alias").isEmpty());
        } catch (StorageException e) {
            assertTrue(false);
        }
        
        File ksFile = new File(this.ksFilename);
        ksFile.delete();
        CredentialWriter credWKS = null;
        try {
            credWKS = this.cwf.getCredentialwriterInstanceForCert(StorageConstants.BASE64_PEM_STORE_TYPE, this.ksFilename, this.base64Password);
            credWKS.storeKeyPair(this.kSTestUtil.certPrivateKey, this.kSTestUtil.certChain, "alias");
            System.out.println("Init Key : " + this.getHexString(this.kSTestUtil.certPrivateKey.getEncoded()));
        } catch (final StorageException e) {
            assertTrue(false);
        }
        assertTrue("KeyStore created", ksFile.exists());
        Set<Certificate> certSet = new HashSet<Certificate>();
        try {
            certSet = b64reader.getAllCertificates("alias");
            ksFile.delete();
        } catch (StorageException e) {
            ksFile.delete();
            assertTrue(true);
        }
        
        //positive case 1: certs and key in the same file
        ksFile = new File("/tmp/getAllCerts64.pem");
        try {
            credWKS = new Base64Writer("",ksFile.getAbsolutePath(),"","", "");
            credWKS.storeKeyPair(kSTestUtil.certPrivateKey, kSTestUtil.certChain, "alias");
        } catch (StorageException e) {
            assertTrue(false);
        }
        assertTrue("KeyStore created", ksFile.exists());
        try {
            b64reader = new Base64Reader("",ksFile.getAbsolutePath(),"","","");
            certSet = b64reader.getAllCertificates("alias");
            ksFile.delete();
            System.out.println("Siiizzzeee "+certSet.size());
            assertTrue(certSet.size() == 2);
        } catch (StorageException e) {
            ksFile.delete();
            assertTrue(false);
        }
        
        // positive case 2: key and certs in different files
        ksFile = new File("/tmp/getAllCerts64Full.crt");
        File keyFile = new File("/tmp/getAllCerts64Full.key");
        try {
            credWKS = new Base64Writer("","",ksFile.getAbsolutePath(),keyFile.getAbsolutePath(), "");
            KeyPair kp = PrepareCertificate.createKeyPair();
            X509Certificate x509Cert = PrepareCertificate.prepareCertificate(kp);
            Certificate[] certArray = { x509Cert };
            credWKS.storeKeyPair(kp.getPrivate(), certArray , "alias");
        } catch (StorageException e) {
            assertTrue(false);
        }
        assertTrue("KeyStore and KeyFile created", ksFile.exists() && keyFile.exists());
        try {
            b64reader = new Base64Reader("","",ksFile.getAbsolutePath(),keyFile.getAbsolutePath(),"");
            certSet = b64reader.getAllCertificates("alias");
            assertTrue(ksFile.delete() &&  keyFile.delete());
            assertTrue(certSet.size() == 1);
        } catch (StorageException e) {
            assertTrue(ksFile.delete() &&  keyFile.delete());
            assertTrue(false);
        }
    }
    
    @Test
    public void testWrongFiles() throws IOException {
        File ksFile = new File("/tmp/wrongb64KS");
        assertTrue(ksFile.createNewFile());
        
        try(FileWriter fw64 = new FileWriter(ksFile.getAbsolutePath(), true);
                BufferedWriter buff64 = new BufferedWriter(fw64);
                PrintWriter wr64 = new PrintWriter(buff64))
        {
            wr64.println("-----BEGIN CERTIFICATE-----");
            wr64.println("wrongcontent");
            wr64.println("-----END CERTIFICATE-----");
        } catch (IOException e) {
            assertTrue(false);
        }
        
        CredentialReader b64reader = new Base64Reader("",ksFile.getAbsolutePath(),"","","");
        try {
            assertTrue(b64reader.getCertificate("alias") == null);
            ksFile.delete();
        } catch (StorageException e) {
            ksFile.delete();
            assertTrue(true);
        }
    }
    
    private String getHexString(final byte[] b) {
        String result = "";
        int max = b.length;
        if (max > 40) {
            max = 40;
        }
        for (int i = 0; i < max; i++) {
            result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result + "...";
    }

}
