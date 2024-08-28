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
package com.ericsson.oss.itpf.security.credmsapi.storage.business;

import java.io.*;
import java.security.*;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;



public class LegacyXMLWriter implements CredentialWriter {

    private static final Logger LOG = LogManager.getLogger(LegacyXMLWriter.class);
    
    private String password;
    private String xmlFilePath;
    private String xmlStoreData;
    
    //final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    //final String END_CERTIFICATE = "-----END CERTIFICATE-----";
    final String BEGIN_ENCRYPTED_PRIVATE_KEY = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
    final String END_ENCRYPTED_PRIVATE_KEY = "-----END ENCRYPTED PRIVATE KEY-----";
    final String lineFeed = System.getProperty("line.separator");

    // algorithm to be used is fixed because of legacy format
    final String encryptionAlgorithmOid = "1.2.840.113549.1.5.3"; //"pbeWithMD5AndDES-CBC"
    // 
    // HARD CODED VALUES
    //
    // The default salt used by Inprise PKCS5 implementation
    private static final byte[] defaultSalt =  { -54, -2, -70, -66, -70, -83, 18, 52};
    private static final int defaultCount =  3;
    
    
    /**
     * 
     */
    private LegacyXMLWriter() {

    }

    /**
     * LegacyXMLWriter
     * 
     * @param xmlFilePath
     * @param password
     * @throws StorageException
     */
    public LegacyXMLWriter(final String xmlFilePath, final String password)
            throws StorageException {
        this();
        this.xmlFilePath = xmlFilePath;
        // note: password MUST exists
        this.password = password;
    }

    
    /* (non-Javadoc)
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter#storeKeyPair(java.security.Key, java.security.cert.Certificate[], java.lang.String)
     */
    @Override
    public void storeKeyPair(final Key key, final Certificate[] certificateChain, final String alias) throws StorageException {
        
        // read data from file or template
        //this.xmlStoreData = this.readXMLfile(this.xmlFilePath);
        this.xmlStoreData = this.readXMLfile(null);
       
        //  Private KEY
        try {
            final String keyString = this.pbeMD5DesCbc((PrivateKey) key, this.encryptionAlgorithmOid, this.password);
            // write pem into the xml
            this.addPemToXml(keyString, this.KEY_TAG, this.KEY_PLACEHOLDER);
            
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException
                | IOException e1) {
            LOG.error(ErrorMsg.API_ERROR_STORAGE_CREATE_PKFILE, "LegacyXML String data");
            throw new StorageException(e1);
        }
        
        //
        //  CERT chain 
        //
        final StringWriter swCer = new StringWriter();
        final JcaPEMWriter pemWriter = new JcaPEMWriter(swCer );        
        // write the certificate path (the chain)
        for (int i=0; i<certificateChain.length; i++) {
            // write certificate to PEM            
            try {
                pemWriter.writeObject(certificateChain[i]);
                pemWriter.flush();
            } catch (final IOException e) {
                LOG.error(ErrorMsg.API_ERROR_STORAGE_CREATE_CERTFILE, "LegacyXML String data");
                throw new StorageException(e);
            }
            //extract PEM string
            final String pemString = swCer.getBuffer().toString();
            // clear the StringWriter
            swCer.getBuffer().setLength(0);
            
            // write pem into the xml
            this.addPemToXml(pemString, this.CERT_TAG, this.CERT_PLACEHOLDER);
        }
        try {
            pemWriter.close();
        } catch (final IOException e) {
            LOG.error(ErrorMsg.API_ERROR_STORAGE_CLOSE_WRITERS);
            throw new StorageException(e);
        }
        //
        this.writeXMLfile(this.xmlStoreData, this.xmlFilePath);

    } // end of storeKeyPair
    

    /* (non-Javadoc)
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter#addTrustedEntry(java.security.cert.Certificate, java.lang.String)
     */
    @Override
    public void addTrustedEntry(final Certificate cert, final String alias) throws StorageException {

        // read data from file 
        this.xmlStoreData = this.readXMLfile(this.xmlFilePath);

        final StringWriter swCer = new StringWriter();
        final JcaPEMWriter pemWriter = new JcaPEMWriter(swCer);

        // write certificate to PEM            
        try {
            pemWriter.writeObject(cert);
            pemWriter.flush();
        } catch (final IOException e) {
            LOG.error(ErrorMsg.API_ERROR_STORAGE_CREATE_CERTFILE, "LegacyXML String data");
            try {
                pemWriter.close();
            } catch (final IOException e1) {
                LOG.error(ErrorMsg.API_ERROR_STORAGE_CLOSE_WRITERS);
            }
            throw new StorageException(e);
        }
        //extract PEM string
        final String pemString = swCer.getBuffer().toString();
        // clear the StringWriter
        swCer.getBuffer().setLength(0);

        // write pem into the xml
        this.addPemToXml(pemString, this.TRUST_TAG, this.TRUST_PLACEHOLDER);

        try {
            pemWriter.close();
        } catch (final IOException e) {
            LOG.error(ErrorMsg.API_ERROR_STORAGE_CLOSE_WRITERS);
            throw new StorageException(e);
        }
        //
        this.writeXMLfile(this.xmlStoreData, this.xmlFilePath);

    } // end of addTrustedEntry
    

    /* (non-Javadoc)
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter#addCrlEntry(java.security.cert.CRL, java.lang.String)
     */
    @Override
    public void addCrlEntry(final CRL crl, final String alias) throws StorageException {
        // TODO Auto-generated method stub
    }

    /* (non-Javadoc)
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter#deleteEntry(java.lang.String)
     */
    @Override
    public void deleteEntry(final String alias) throws StorageException {
        // TODO Auto-generated method stub
    }
    
    
    /**
     * addPemToXml
     * 
     * store data into xmlStoreData
     * 
     * @param pemKey
     */
    private boolean addPemToXml(final String rawPem, final String tag, final String placeholder) {

        Boolean valid_data = false;
        final StringBuffer output = new StringBuffer("");
        final String[] line = this.xmlStoreData.split(this.lineFeed);
        for (final String l : line) {
            // search for placeholder where to add the PEM
            if (l.trim().contentEquals(placeholder)) {
                
                // insert the tags and the PEM
                output.append("<"+tag+">"+this.lineFeed);
                output.append(rawPem);
                output.append("</"+tag+">"+this.lineFeed);                
                
                valid_data = true;
                
            } 
            // append to buffer all the content of xmlStoreData
            output.append(l + this.lineFeed);
        }
        // update the xmlStoreData
        this.xmlStoreData = output.toString();
        return valid_data;
        
    } // end of addPemToXml

    
    /**
     * pbeMD5DesCbc
     * 
     * @param privKey
     * @param pass
     * @return String
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws IllegalBlockSizeException
     * @throws IOException
     * @throws BadPaddingException
     */
    private String pbeMD5DesCbc(final PrivateKey privKey, final String algoOid, final String pass) 
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, 
            InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, IOException, 
            BadPaddingException {   
        
        final char[] charPassword = pass.toCharArray();

// previous version with Salt choose ramdomly
//        final Random r = new SecureRandom();
//        final byte[] salt = new byte[8];
//        r.nextBytes(salt);
//        final int iCount = 2048;
        
        final byte[] salt = this.defaultSalt;
        final int iCount = this.defaultCount;

        final PBEKeySpec pbeKeySpec = new PBEKeySpec(charPassword, salt, iCount);
        final PBEParameter pbeParams = new PBEParameter(pbeKeySpec.getSalt(), pbeKeySpec.getIterationCount());
        final SecretKeyFactory secretKeyFact = SecretKeyFactory.getInstance(algoOid , "BC");
        
        final Cipher cipher = Cipher.getInstance(algoOid , "BC" );

        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFact.generateSecret(pbeKeySpec));

        final ASN1InputStream derin = new ASN1InputStream(privKey.getEncoded());
        final PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(derin.readObject());
        derin.close();

        final byte[] wrappedKey = cipher.doFinal(pkInfo.getEncoded());

        final ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(algoOid);
        final AlgorithmIdentifier algId = new AlgorithmIdentifier(oid, pbeParams);
        final org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo pInfo = new org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo(algId, wrappedKey);

        final StringBuilder out = new StringBuilder("");
        out.append(this.BEGIN_ENCRYPTED_PRIVATE_KEY+this.lineFeed);
        out.append(this.base64l64(pInfo).toString()+this.lineFeed);
        out.append(this.END_ENCRYPTED_PRIVATE_KEY+this.lineFeed);
        
        //System.out.println(out.toString());
        
        return out.toString();
        
    } //end of pbeMD5DesCbc
    
    
    /**
     * base64l64
     * 
     * @param pInfo
     * @return
     * @throws IOException
     */
    private StringBuilder base64l64(
                    final org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo pInfo)
                    throws IOException {

        final String encoded = Base64.encodeBase64String(pInfo.getEncoded());
        final StringBuilder s = new StringBuilder(encoded);          
        final StringBuilder s64 = new StringBuilder("");
        final String[] sLines = s.toString().split(this.lineFeed);
        s.delete(0, s.length()); 
        for ( Integer i = 0; i < sLines.length; i++){
                    s.append(sLines[i].toString());
            }
        for ( Integer i = 0; i < s.length();i=i+64){
            if( s.length() - i > 64) {
                    s64.append(s.subSequence(i, i+64));
                    s64.append(this.lineFeed);
            }
            else {
                    s64.append(s.subSequence(i, s.length()));
            }
        }
        return s64;
    }
    
    
    
    //
    // Legacy XML keystore definition
    //
    
    final String XML_TEMPLATE = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> " + this.lineFeed +
    "<slscredentials> " + this.lineFeed +
    "  <responsemessage>ok</responsemessage> " + this.lineFeed +
    "  <certificatechain> " + this.lineFeed +
    "  </certificatechain> " + this.lineFeed +
    "  <trustedcertificates> " + this.lineFeed +
    "  </trustedcertificates> " + this.lineFeed +
    "  <properties> " + this.lineFeed +
    "  </properties> " + this.lineFeed +
    "</slscredentials> " + this.lineFeed + this.lineFeed;

    final String KEY_TAG = "privatekey";
    final String CERT_TAG = "certificate";
    final String TRUST_TAG = "certificate"; 
    
    final String KEY_PLACEHOLDER = "<certificatechain>";
    final String CERT_PLACEHOLDER = "</certificatechain>";
    final String TRUST_PLACEHOLDER = "</trustedcertificates>";
    
    //
    // file utility
    //
    
    /**
     * readXMLfile
     * 
     * @param fileName
     * @return
     */
    private String readXMLfile(final String fileName) {

        if (fileName == null || fileName.equals("")) {
            return this.XML_TEMPLATE;
        }
        final StringBuffer output = new StringBuffer("");
        String l;
        try {
            final BufferedReader br = new BufferedReader(new FileReader(fileName));
            // store the whole buffer directly into string
            while ((l = br.readLine()) != null) { // while loop begins here
                output.append(l+ this.lineFeed);
            } // end while
            br.close();
            return output.toString();
           
        } catch (final IOException e) {
            // if file not exist fill the xml data with template
            return this.XML_TEMPLATE;
        }        
    }
    
    /**
     * writeXMLfile
     * 
     * uses xmlFilePath and xmlStoreData
     */
    private void writeXMLfile(final String rawData, final String fileName) {
        
        //System.out.println(this.xmlStoreData);
        
        try {
            final File xmlFile = new File(fileName);
            final BufferedWriter writer = new BufferedWriter(new FileWriter(xmlFile));
            writer.write(rawData);
            writer.close();
        } catch (final IOException e) {
            LOG.error(ErrorMsg.API_ERROR_STORAGE_CREATE_CERTFILE,this.xmlFilePath);
        }        
    }
    
   
//  // PRINT OF SECURITY PROVIDER CAPABILITY
//  
//  final Provider      provider = Security.getProvider("BC");
//  System.out.println("===== Provider : "+provider.getName());
//  final Iterator<Object>  it = provider.keySet().iterator();
//  
//  while (it.hasNext())
//  {
//      String        entry = (String)it.next();
//      
//      // this indicates the entry refers to another entry
//      
//      if (entry.startsWith("Alg.Alias."))
//      {
//          entry = entry.substring("Alg.Alias.".length());
//      }
//      
//      final String  factoryClass = entry.substring(0, entry.indexOf('.'));
//      final String  name = entry.substring(factoryClass.length() + 1);
//
//      System.out.println(factoryClass + ": " + name);
//  }
// 
//
    
} // end of LegacyXMLWriter

