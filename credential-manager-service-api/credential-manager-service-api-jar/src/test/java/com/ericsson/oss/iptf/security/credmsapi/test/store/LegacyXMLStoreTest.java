package com.ericsson.oss.iptf.security.credmsapi.test.store;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.ericsson.oss.iptf.security.credmsapi.test.utils.KeyAndCertUtil;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.LegacyXMLReader;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.LegacyXMLWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;

@RunWith(JUnit4.class)
public class LegacyXMLStoreTest {

    KeyAndCertUtil kSTestUtil = new KeyAndCertUtil();


    final String xmlFilename = "/tmp/legacykeystore.xml";

    final String base64Password = "pippo";

    @Before
    public void setup() {
        // prepareParameters();
        this.kSTestUtil.prepareParameters();
        //        this.kSTestUtil.prepareCert();
        //        this.kSTestUtil.prepareCAcert();
    }

    @Test
    public void testLegacyXMLStore() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {


        assertTrue("Certificate was not read correctly", this.kSTestUtil.certChain.length != 0);

        //
        // WRITE XML FILE
        //
        final File ksFile = new File(this.xmlFilename);
        LegacyXMLWriter legacyWriter = null;
        ksFile.delete();
        try {
            legacyWriter = new LegacyXMLWriter(this.xmlFilename, this.base64Password);
            legacyWriter.storeKeyPair(this.kSTestUtil.certPrivateKey, this.kSTestUtil.certChain, "alias");
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        assertTrue("XmlWriter created", legacyWriter != null);
        assertTrue("XmlStore created", ksFile.exists());        
        System.out.println("XmlStore written : "+this.xmlFilename);
        
        // write Trust
        final long before = ksFile.lastModified();
        // pause added to avoid after=before
        try {
            Thread.sleep(2000);
        } catch (final InterruptedException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        try {
            legacyWriter.addTrustedEntry(this.kSTestUtil.CaChain[0], "alias");
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        final long after = ksFile.lastModified();
        assertTrue("XmlStore modified", after != before);
        System.out.println("XmlStore modified : "+this.xmlFilename);
        
        //
        // READ PHASE
        //
        LegacyXMLReader legacyReader = null;
        Key myKey = null;
        try {
            legacyReader = new LegacyXMLReader(this.xmlFilename, this.base64Password);
            myKey = legacyReader.getPrivateKey("alias");
            assertTrue("Key read", myKey != null);
            
            // using reflection to invoke LegacyXMLReader private Method
            Class cls;
            Method method = null;
            Object obj = null;
            try {
                cls = Class.forName("com.ericsson.oss.itpf.security.credmsapi.storage.business.LegacyXMLReader");
                obj = LegacyXMLReader.class.getDeclaredConstructor(String.class, String .class).newInstance(this.xmlFilename, this.base64Password);
                method = LegacyXMLReader.class.getDeclaredMethod("getHexString", byte[].class);
                method.setAccessible(true);
            } catch (final Exception e2) {        
                e2.printStackTrace();
            }
            System.out.println("Read Key : " + (String)method.invoke(obj,myKey.getEncoded()));
        } catch (final StorageException e) {
            assertTrue(false);
        }               
        assertTrue("Key check", this.kSTestUtil.certPrivateKey.equals(myKey));

        Certificate myCert = null;
        try {
            myCert = legacyReader.getCertificateChain("alias")[0];
            assertTrue("Certificate read", myCert != null);
            System.out.println("Read Cert : " + myCert.getType());
        } catch (final StorageException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        boolean flag = true;
        try {
            for (int i=0;i<myCert.getEncoded().length; i++) {
                final byte ksByte = this.kSTestUtil.certChain[0].getEncoded()[i];
//                System.out.println("check certificate, byte n."+i+" -> "+ksByte+"="+myCert.getEncoded()[i]);
                flag = flag && (ksByte == myCert.getEncoded()[i]);
            }
        } catch (final CertificateEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        assertTrue("Certificate check", flag);
        try {
            assertTrue(legacyReader.getAllCertificates("rootAlias") == null);
            assertTrue(legacyReader.getCRLs("alias") == null);
        } catch (StorageException e) {
            assertTrue(false);
        }
        ksFile.delete();
    }
    
    @Test
    public void testLegacyXMLNullPointers() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        Class cls;
        Method method = null;
        Object obj = null;
        try {
            cls = Class.forName("com.ericsson.oss.itpf.security.credmsapi.storage.business.LegacyXMLReader");
            obj = LegacyXMLReader.class.getDeclaredConstructor(String.class, String .class).newInstance("", "");
            method = LegacyXMLReader.class.getDeclaredMethod("readXMLfile", String.class);
            method.setAccessible(true);
        } catch (final Exception e2) {        
            e2.printStackTrace();
        }
        String arg = null;
        String result = (String)method.invoke(obj,arg);
        assertTrue(result == null);
        arg = "";
        result = (String)method.invoke(obj,arg);
        assertTrue(result == null);
        
        try {
            cls = Class.forName("com.ericsson.oss.itpf.security.credmsapi.storage.business.LegacyXMLWriter");
            obj = LegacyXMLWriter.class.getDeclaredConstructor(String.class, String .class).newInstance("", "");
            method = LegacyXMLWriter.class.getDeclaredMethod("readXMLfile", String.class);
            method.setAccessible(true);
        } catch (final Exception e2) {        
            e2.printStackTrace();
        }
        arg = "";
        result = (String)method.invoke(obj,arg);
        assertTrue(result != null);
    }
    
    @Test
    public void testAddTrustedException() {
        final File ksFile = new File(this.xmlFilename);
        LegacyXMLWriter legacyWriter = null;
        ksFile.delete();
        try {
            ksFile.createNewFile();
        } catch (IOException e1) {
            assertTrue(false);
        }
        ksFile.setWritable(false,true);
        
        try {
            legacyWriter = new LegacyXMLWriter(this.xmlFilename, this.base64Password);
            legacyWriter.addTrustedEntry(this.kSTestUtil.CaChain[0], "alias");
        } catch (final StorageException e) {
            assertTrue(false);
        }

        assertTrue(ksFile.delete());
        
    }

}
