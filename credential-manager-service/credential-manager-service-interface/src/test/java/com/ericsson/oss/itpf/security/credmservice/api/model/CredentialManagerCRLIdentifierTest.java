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

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.Properties;

import com.ericsson.oss.itpf.security.keymanagement.KeyGenerator;

import java.security.KeyPair;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Test;




public class CredentialManagerCRLIdentifierTest {
	
	private  static CredentialManagerCRLIdentifier testCRL1 = null; 

	private  static CredentialManagerCRLIdentifier testCRL2 = null; 

   
  
    public static X509CRL generateCrl(int crlNumber) {
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        try {
        	
        	final Date thisUpdate = new Date(System.currentTimeMillis());
        	
        	
        	final Date 	nextUpdate = new Date(System.currentTimeMillis() + (10 * 24L * 60L * 60L * 1000L));
        	
        	
            final X500Name issuerName = new X500Name("CN=pippo");
            final X509v2CRLBuilder crlGen = new X509v2CRLBuilder(issuerName, thisUpdate);

            /*
             * Create KeyPair parameter
             */
            final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", 2048);

            crlGen.setNextUpdate(nextUpdate);
            crlGen.addCRLEntry(BigInteger.ONE, thisUpdate, CRLReason.PRIVILEGE_WITHDRAWN);
            if (crlNumber != 0) {
            	crlGen.addExtension(X509Extensions.CRLNumber, false, new CRLNumber(BigInteger.valueOf(crlNumber)));
            }
            final ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WITHRSAENCRYPTION").setProvider("BC").build(keyPair.getPrivate());
            final X509CRLHolder crlHolder = crlGen.build(sigGen);

            final CredentialManagerX509CRL crl = new CredentialManagerX509CRL(crlHolder.getEncoded());
            
            return crl.retrieveCRL();
           
        } catch (final Exception e) {
            assertTrue("generateCrl failed!", false);
        }
        return null;

    }

    @Test
    public void crlCreation() {

    	testCRL1  = new CredentialManagerCRLIdentifier(this.generateCrl((int) 10));
    	
    	int   hashcode = testCRL1.hashCode(); 

    	System.out.println("hashcode is "+hashcode);
    	assertTrue("crlCreation not generated CRL",  testCRL1 != null);
    	assertTrue("crlCreation wrong hashCode ",    hashcode  != 31 );
    	
    }

    @Test
    public void crlEqual01() {

    	testCRL1  = new CredentialManagerCRLIdentifier(this.generateCrl((int) 10));
    	testCRL2 = testCRL1; 

    	assertTrue("crlEqual01 equals error",  testCRL1.equals(testCRL2) == true);
    	assertTrue("crlEqual01 compareTo error",  testCRL1.compareTo(testCRL2) == 0);
    }

    @Test
    public void crlEqual02() {
    	testCRL1  = new CredentialManagerCRLIdentifier(this.generateCrl((int) 0));
    	Date thisUpdate = new Date(System.currentTimeMillis());
    	Date myDate = null; 
    	byte[] signature = { (byte) 0x65, (byte)0x10, (byte)0xf3, (byte)0x29};

    	testCRL1.setNextUpdate(thisUpdate);
    	testCRL1.setThisUpdate(thisUpdate);
    	testCRL1.setIssuerName("pippo");
    	testCRL1.setSignature(signature);
    	testCRL1.setCrlNumber((BigInteger.valueOf(1)));

    	assertTrue ("wrong thisUpdate ", testCRL1.getThisUpdate().equals(thisUpdate));
    	assertTrue ("wrong nextUpdate ", testCRL1.getNextUpdate().equals(thisUpdate));
    	assertTrue ("wrong IssuerName",  testCRL1.getIssuerName().equals("pippo"));    
    	assertTrue ("wrong signature",   testCRL1.getSignature().equals(signature)); 
    	assertTrue ("wrong crl",         testCRL1.getCrlNumber().equals(BigInteger.valueOf(1)));


    	testCRL2 = testCRL1; 

    	assertTrue("crlEqual02 equals error",  testCRL1.equals(testCRL2) == true);
    	assertTrue("crlEqual02 compare error", testCRL1.compareTo(testCRL2) == 0);
    }

    @Test
    public void crlEqual03() {
    	testCRL1  = new CredentialManagerCRLIdentifier();
    	testCRL2  = new CredentialManagerCRLIdentifier();
    	Date thisUpdate = new Date(System.currentTimeMillis());

    	byte[] signature = { (byte) 0x65, (byte)0x10, (byte)0xf3, (byte)0x29};

    	testCRL1.setNextUpdate(thisUpdate);
    	testCRL1.setThisUpdate(thisUpdate);
    	testCRL1.setIssuerName("pippo");
    	testCRL1.setSignature(signature);
    	testCRL1.setCrlNumber((BigInteger.valueOf(1)));

    	testCRL2.setNextUpdate(thisUpdate);
    	testCRL2.setThisUpdate(thisUpdate);
    	testCRL2.setIssuerName("pippo");
    	testCRL2.setSignature(signature);
    	testCRL2.setCrlNumber((BigInteger.valueOf(1)));



    	assertTrue("crlEqual03 equals error",  testCRL1.equals(testCRL2) == true);
    	assertTrue("crlEqual03 compare error",  testCRL1.compareTo(testCRL2) == 0);
    }

    @Test
    public void crlNotEqual01() {

    	Date thisUpdate = new Date(System.currentTimeMillis());
    	testCRL1  = new CredentialManagerCRLIdentifier(this.generateCrl((int) 10));
    	testCRL2 =  new CredentialManagerCRLIdentifier(this.generateCrl((int) 10));

    	testCRL1.setThisUpdate(thisUpdate);
    	testCRL1.setNextUpdate(thisUpdate);



    	assertTrue("crlNotEqual01 equals error", testCRL1.equals(testCRL2) == false );
    	assertTrue("crlWrongCompare01 compareTo error", testCRL1.compareTo(testCRL2) != 0 );


    }
    @Test
    public void crlNotEqual02() {
    	Date thisUpdate = new Date(System.currentTimeMillis());
    	testCRL1  = new CredentialManagerCRLIdentifier(this.generateCrl((int) 10));

    	assertTrue("crlNotEqual02 equals error", testCRL1.equals(thisUpdate) == false );

    }
    @Test
    public void crlNotEqual03() {

    	testCRL1  = new CredentialManagerCRLIdentifier(this.generateCrl((int) 10));

    	assertTrue("crlNotEqual03 equals error", testCRL1.equals(null) == false );

    }
    @Test
    public void crlNotEqual04() {

    	testCRL1  = new CredentialManagerCRLIdentifier(this.generateCrl((int) 10));
    	testCRL2  = new CredentialManagerCRLIdentifier(this.generateCrl((int) 20));


    	assertTrue("crlNotEqual04 equals error", testCRL1.equals(testCRL2) == false );
    	assertTrue("crlNotEqual04 compareTo error", testCRL1.compareTo(testCRL2) != 0 );
    }
    @Test
    public void crlNotEqual05() {
    	testCRL1  = new CredentialManagerCRLIdentifier(this.generateCrl((int) 0));
    	testCRL2  = new CredentialManagerCRLIdentifier(this.generateCrl((int) 20));


    	assertTrue("crlNotEqual05-1 equals error", testCRL1.equals(testCRL2) == false );
    	assertTrue("crlNotEqual05-2 equals error", testCRL2.equals(testCRL1) == false );
    	assertTrue("crlNotEqual05-1 compareTo error", testCRL1.compareTo(testCRL2) != 0 );
    	assertTrue("crlNotEqual05-2 compareTo error", testCRL2.compareTo(testCRL1) != 0 );


    }


    @Test
    public void crlNotEqual06() {
    	testCRL1  = new CredentialManagerCRLIdentifier();
    	testCRL2  = new CredentialManagerCRLIdentifier();

    	Date thisUpdate = new Date(System.currentTimeMillis());
    	Date myDate = null; 
    	byte[] signature = { (byte) 0x65, (byte)0x10, (byte)0xf3, (byte)0x29};

    	testCRL1.setNextUpdate(thisUpdate);
    	testCRL2.setNextUpdate(thisUpdate);

    	testCRL1.setThisUpdate(thisUpdate);
    	testCRL2.setThisUpdate(thisUpdate);

    	testCRL1.setIssuerName("pippo");

    	testCRL1.setSignature(signature);
    	testCRL2.setSignature(signature);

    	testCRL1.setCrlNumber((BigInteger.valueOf(1)));
    	testCRL2.setCrlNumber((BigInteger.valueOf(1)));



    	assertTrue("crlNotEqual06-1 equals error", testCRL1.equals(testCRL2) == false );
    	assertTrue("crlNotEqual06-2 equals error", testCRL2.equals(testCRL1) == false );
    	assertTrue("crlNotEqual06-1 compareTo error", testCRL1.compareTo(testCRL2) != 0 );
    	assertTrue("crlNotEqual06-2 compareTo error", testCRL2.compareTo(testCRL1) != 0 );


    }

    @Test
    public void crlNotEqual07() {
    	testCRL1  = new CredentialManagerCRLIdentifier();
    	testCRL2  = new CredentialManagerCRLIdentifier();

    	Date thisUpdate = new Date(System.currentTimeMillis());
    	Date myDate = null; 
    	byte[] signature = { (byte) 0x65, (byte)0x10, (byte)0xf3, (byte)0x29};

    	testCRL1.setNextUpdate(thisUpdate);
    	testCRL2.setNextUpdate(thisUpdate);

    	testCRL1.setThisUpdate(thisUpdate);


    	testCRL1.setIssuerName("pippo");
    	testCRL2.setIssuerName("pippo");

    	testCRL1.setSignature(signature);
    	testCRL2.setSignature(signature);

    	testCRL1.setCrlNumber((BigInteger.valueOf(1)));
    	testCRL2.setCrlNumber((BigInteger.valueOf(1)));



    	assertTrue("crlNotEqual07-1 equals error", testCRL1.equals(testCRL2) == false );
    	assertTrue("crlNotEqual07-2 equals error", testCRL2.equals(testCRL1) == false );
    	assertTrue("crlNotEqual07-1 compareTo error", testCRL1.compareTo(testCRL2) != 0 );
    	assertTrue("crlNotEqual07-2 compareTo error", testCRL2.compareTo(testCRL1) != 0 );


    }

    @Test
    public void crlNotEqual08() {
    	testCRL1  = new CredentialManagerCRLIdentifier();
    	testCRL2  = new CredentialManagerCRLIdentifier();

    	Date thisUpdate = new Date(System.currentTimeMillis());
    	
    	byte[] signature = { (byte) 0x65, (byte)0x10, (byte)0xf3, (byte)0x29};

    	testCRL1.setNextUpdate(thisUpdate);
    	testCRL2.setNextUpdate(thisUpdate);


    	testCRL1.setThisUpdate(thisUpdate);
    	testCRL2.setThisUpdate(thisUpdate);

    	testCRL1.setIssuerName("pippo");
    	testCRL2.setIssuerName("pippo");

    	testCRL1.setSignature(signature);


    	testCRL1.setCrlNumber((BigInteger.valueOf(1)));
    	testCRL2.setCrlNumber((BigInteger.valueOf(1)));



    	assertTrue("crlNotEqual08-1 equals error", testCRL1.equals(testCRL2) == false );
    	assertTrue("crlNotEqual08-2 equals error", testCRL2.equals(testCRL1) == false );
    	assertTrue("crlNotEqual08-1 compareTo error", testCRL1.compareTo(testCRL2) != 0 );
    	assertTrue("crlNotEqual08-2 compareTo error", testCRL2.compareTo(testCRL1) != 0 );


    }

    @Test
    public void crlNotEqual09() {
    	testCRL1  = new CredentialManagerCRLIdentifier();
    	testCRL2  = new CredentialManagerCRLIdentifier();

    	Date thisUpdate = new Date(System.currentTimeMillis());
    	 
    	byte[] signature = { (byte) 0x65, (byte)0x10, (byte)0xf3, (byte)0x29};

    	testCRL1.setNextUpdate(thisUpdate);

    	testCRL1.setThisUpdate(thisUpdate);
    	testCRL2.setThisUpdate(thisUpdate);

    	testCRL1.setIssuerName("pippo");
    	testCRL2.setIssuerName("pippo");

    	testCRL1.setSignature(signature);
    	testCRL2.setSignature(signature);

    	testCRL1.setCrlNumber((BigInteger.valueOf(1)));
    	testCRL2.setCrlNumber((BigInteger.valueOf(1)));



    	assertTrue("crlNotEqual09-1 equals error", testCRL1.equals(testCRL2) == false );
    	assertTrue("crlNotEqual09-2 equals error", testCRL2.equals(testCRL1) == false );
    	assertTrue("crlNotEqual09-1 compareTo error", testCRL1.compareTo(testCRL2) != 0 );
    	assertTrue("crlNotEqual09-2 compareTo error", testCRL2.compareTo(testCRL1) != 0 );


    }

    @Test
    public void crlNotEqual10() {
    	testCRL1  = new CredentialManagerCRLIdentifier();
    	testCRL2  = new CredentialManagerCRLIdentifier();

    	Date thisUpdate = new Date(1000);
    	Date newDate  = new Date(2000);
    	
    	byte[] signature = { (byte) 0x65, (byte)0x10, (byte)0xf3, (byte)0x29};

    	testCRL1.setNextUpdate(thisUpdate);
    	testCRL2.setNextUpdate(newDate);


    	testCRL1.setThisUpdate(thisUpdate);
    	testCRL2.setThisUpdate(thisUpdate);

    	testCRL1.setIssuerName("pippo");
    	testCRL2.setIssuerName("pippo");

    	testCRL1.setSignature(signature);
    	testCRL2.setSignature(signature);

    	testCRL1.setCrlNumber((BigInteger.valueOf(1)));
    	testCRL2.setCrlNumber((BigInteger.valueOf(1)));



    	assertTrue("crlNotEqual10-1 equals error", testCRL1.equals(testCRL2) == false );
    	assertTrue("crlNotEqual10-2 equals error", testCRL2.equals(testCRL1) == false );
    	assertTrue("crlNotEqual10-1 compareTo error", testCRL1.compareTo(testCRL2) != 0 );
    	assertTrue("crlNotEqual10-2 compareTo error", testCRL2.compareTo(testCRL1) != 0 );


    }
    
    @Test
    public void crlNotEqual11() {
    	testCRL1  = new CredentialManagerCRLIdentifier();
    	testCRL2  = new CredentialManagerCRLIdentifier();

    	Date thisUpdate = new Date(1000);
    	Date newDate  = new Date(2000);
    	
    	Date myDate = null; 
    	byte[] signature = { (byte) 0x65, (byte)0x10, (byte)0xf3, (byte)0x29};

    	testCRL1.setNextUpdate(thisUpdate);
    	testCRL1.setNextUpdate(thisUpdate);


    	testCRL1.setThisUpdate(newDate);
    	testCRL2.setThisUpdate(thisUpdate);

    	testCRL1.setIssuerName("pippo");
    	testCRL2.setIssuerName("pippo");

    	testCRL1.setSignature(signature);
    	testCRL2.setSignature(signature);

    	testCRL1.setCrlNumber((BigInteger.valueOf(1)));
    	testCRL2.setCrlNumber((BigInteger.valueOf(1)));



    	assertTrue("crlNotEqual11-1 equals error", testCRL1.equals(testCRL2) == false );
    	assertTrue("crlNotEqual11-2 equals error", testCRL2.equals(testCRL1) == false );
    	assertTrue("crlNotEqual11-1 compareTo error", testCRL1.compareTo(testCRL2) != 0 );
    	assertTrue("crlNotEqual11-2 compareTo error", testCRL2.compareTo(testCRL1) != 0 );


    }
    

    @Test
    public void crlNotEqual12() {
    	testCRL1  = new CredentialManagerCRLIdentifier();
    	testCRL2  = new CredentialManagerCRLIdentifier();

    	Date thisUpdate = new Date(System.currentTimeMillis());
    	

    	byte[] signature = { (byte) 0x65, (byte)0x10, (byte)0xf3, (byte)0x29};

    	testCRL1.setNextUpdate(thisUpdate);
    	testCRL2.setNextUpdate(thisUpdate);


    	testCRL1.setThisUpdate(thisUpdate);
    	testCRL2.setThisUpdate(thisUpdate);

    	testCRL1.setIssuerName("paperino");
    	testCRL2.setIssuerName("pippo");

    	testCRL1.setSignature(signature);
    	testCRL2.setSignature(signature);

    	testCRL1.setCrlNumber((BigInteger.valueOf(1)));
    	testCRL2.setCrlNumber((BigInteger.valueOf(1)));



    	assertTrue("crlNotEqual12-1 equals error", testCRL1.equals(testCRL2) == false );
    	assertTrue("crlNotEqual12-2 equals error", testCRL2.equals(testCRL1) == false );
    	assertTrue("crlNotEqual12-1 compareTo error", testCRL1.compareTo(testCRL2) != 0 );
    	assertTrue("crlNotEqual12-2 compareTo error", testCRL2.compareTo(testCRL1) != 0 );


    }

    @Test
    public void crlNotEqual13() {
    	testCRL1  = new CredentialManagerCRLIdentifier();
    	testCRL2  = new CredentialManagerCRLIdentifier();

    	Date thisUpdate = new Date(System.currentTimeMillis());
    	
    
    	byte[] signature1 = { (byte) 0x65, (byte)0x10, (byte)0xf3, (byte)0x29};
    	byte[] signature2 = { (byte) 0x65, (byte)0x10, (byte)0xf3, (byte)0x49};

    	testCRL1.setNextUpdate(thisUpdate);
    	testCRL2.setNextUpdate(thisUpdate);


    	testCRL1.setThisUpdate(thisUpdate);
    	testCRL2.setThisUpdate(thisUpdate);

    	testCRL1.setIssuerName("paperino");
    	testCRL2.setIssuerName("paperino");

    	testCRL1.setSignature(signature1);
    	testCRL2.setSignature(signature2);

    	testCRL1.setCrlNumber((BigInteger.valueOf(1)));
    	testCRL2.setCrlNumber((BigInteger.valueOf(1)));



    	assertTrue("crlNotEqual13-1 equals error", testCRL1.equals(testCRL2) == false );
    	assertTrue("crlNotEqual13-2 equals error", testCRL2.equals(testCRL1) == false );
    	assertTrue("crlNotEqual13-1 compareTo error", testCRL1.compareTo(testCRL2) != 0 );
    	assertTrue("crlNotEqual13-2 compareTo error", testCRL2.compareTo(testCRL1) != 0 );


    }


    @Test
    public void crlNotEqual14() {
    	testCRL1  = new CredentialManagerCRLIdentifier();
    	testCRL2  = new CredentialManagerCRLIdentifier();

    	Date thisUpdate = new Date(System.currentTimeMillis());
    	
    	
    	Date myDate = null; 
    	byte[] signature1 = { (byte) 0x65, (byte)0x10, (byte)0xf3, (byte)0x29};
    	byte[] signature2 = { (byte) 0x65, (byte)0x10, (byte)0xf3};
    	
  

    	testCRL1.setNextUpdate(thisUpdate);
    	testCRL2.setNextUpdate(thisUpdate);


    	testCRL1.setThisUpdate(thisUpdate);
    	testCRL2.setThisUpdate(thisUpdate);

    	testCRL1.setIssuerName("paperino");
    	testCRL2.setIssuerName("paperino");

    	testCRL1.setSignature(signature1);
    	testCRL2.setSignature(signature2);
    	
   

    	testCRL1.setCrlNumber((BigInteger.valueOf(1)));
    	testCRL2.setCrlNumber((BigInteger.valueOf(1)));



    	assertTrue("crlNotEqual14-1 equals error", testCRL1.equals(testCRL2) == false );
    	assertTrue("crlNotEqual14-2 equals error", testCRL2.equals(testCRL1) == false );
    	assertTrue("crlNotEqual14-1 compareTo error", testCRL1.compareTo(testCRL2) != 0 );
    	assertTrue("crlNotEqual14-2 compareTo error", testCRL2.compareTo(testCRL1) != 0 );


    }





}
