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

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.encoders.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;

public class LegacyXMLReader implements CredentialReader {

    private static final Logger LOG = LogManager.getLogger(LegacyXMLReader.class);

    final String lineFeed = System.getProperty("line.separator");

    private String xmlFilePath;
    private String password;
    private String xmlStoreData;

    //@SuppressWarnings("unused")
    private LegacyXMLReader() {

    }

    public LegacyXMLReader(final String xmlFilePath, final String password) throws StorageException {
        this();
        this.xmlFilePath = xmlFilePath;
        // note: password MUST exists
        this.password = password;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#getPrivateKey(java.lang.String)
     */
    @Override
    public Key getPrivateKey(final String alias) throws StorageException {

        // read the file
        this.xmlStoreData = this.readXMLfile(this.xmlFilePath);

        // find the key
        final String[] keyPem = this.readPemFromXML(LegacyXMLReader.KEY_TAG, LegacyXMLReader.KEY_START_PLACEHOLDER, LegacyXMLReader.KEY_END_PLACEHOLDER);

        //parse the first PEM

        // remove the BEGIN and END lines
        final String[] temp = keyPem[0].split(this.lineFeed);
        final Integer len = temp.length - 1;
        final StringBuffer out = new StringBuffer("");
        for (Integer i = 1; i < len; i++) {
            out.append(temp[i]);
            out.append("\n");
        }
        // decrypt and convert 
        Key myKey = null;
        try {
            myKey = this.convertPEMtoKEY(out.toString(), this.password);

            //            System.out.println("KEY vvvvvvvvvvvvvvvvvvvvvv");
            //            System.out.println(myKey.toString());       
            //            System.out.println(this.getHexString(myKey.getEncoded()));     
            //            System.out.println("KEY ^^^^^^^^^^^^^^^^^^^^^^\n\n");   

        } catch (final Exception e) {
            LOG.error(ErrorMsg.API_ERROR_STORAGE_CONVERT_PRIVATEKEY, alias);
            throw new StorageException(e);
        }
        return myKey;

    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#getCertificateChain(java.lang.String)
     */
    @Override
    public Certificate[] getCertificateChain(final String alias) throws StorageException {

        // read the file
        this.xmlStoreData = this.readXMLfile(this.xmlFilePath);

        // find the certificates
        final String[] certPem = this.readPemFromXML(LegacyXMLReader.CERT_TAG, LegacyXMLReader.CERT_START_PLACEHOLDER, LegacyXMLReader.CERT_END_PLACEHOLDER);

        final List<Certificate> certList = new ArrayList<Certificate>();
        for (final String certString : certPem) {
            Certificate oneCert;
            try {
                //parse the first PEM
                oneCert = this.convertPEMtoCERT(certString);
                certList.add(oneCert);

                //                System.out.println("CERT vvvvvvvvvvvvvvvvvvvvvv");
                //                System.out.println(oneCert.toString());
                //                System.out.println("CERT ^^^^^^^^^^^^^^^^^^^^^^\n\n");

            } catch (final CertificateException | IOException e) {
                LOG.error(ErrorMsg.API_ERROR_STORAGE_CONVERT_CERT, this.xmlFilePath);
                throw new StorageException(e);
            }
        }
        return certList.toArray(new Certificate[certList.size()]);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#getCertificate(java.lang.String)
     */
    @Override
    public Certificate getCertificate(final String alias) throws StorageException {

        // We assume that first element of the chain is the End Entity Certificate
        return this.getCertificateChain(alias)[0];
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#getAllCertificates(java.lang.String)
     */
    @Override
    public Set<Certificate> getAllCertificates(final String rootAlias) throws StorageException {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#getCRLs(java.lang.String)
     */
    @Override
    public Set<CRL> getCRLs(final String alias) throws StorageException {
        // TODO Auto-generated method stub
        return null;
    }

    //
    // DECRYPT
    //

    /**
     * convertPEMtoCERT
     * 
     * @param pem
     * @return
     * @throws IOException
     * @throws CertificateException
     * @throws StorageException
     */
    private Certificate convertPEMtoCERT(final String pem) throws IOException, CertificateException {

        X509Certificate x509cert = null;

        final StringReader entryReader = new StringReader(pem);
        final PEMParser pp = new PEMParser(entryReader);
        final Object obj = pp.readObject();
        if (obj instanceof X509CertificateHolder) {

            final X509CertificateHolder parsed = (X509CertificateHolder) obj;
            final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

            x509cert = converter.getCertificate(parsed);
        }
        return x509cert;
    }

    /**
     * decodePbeMD5DesCbc
     * 
     * @param encodedIn
     * @param pass
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws IllegalBlockSizeException
     * @throws IOException
     * @throws BadPaddingException
     * @throws Base64DecodingException
     */
    public Key convertPEMtoKEY(final String encodedIn, final String pass) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
            InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {

        final char[] password = pass.toCharArray();
        // decodifica Base64
        final ASN1InputStream ais = new ASN1InputStream(Base64.decode(encodedIn));

        final Object asnObject = ais.readObject();
        final ASN1Sequence sequence = (ASN1Sequence) asnObject;
        ais.close();

        //Ricostruzione ASN1 dell'EncryptedPrivateKeyInfo        
        final EncryptedPrivateKeyInfo pInfo = EncryptedPrivateKeyInfo.getInstance(sequence);

        //Lettura dei parametri dell'algoritmo di encryption pbe pkcs5
        final AlgorithmIdentifier algId = pInfo.getEncryptionAlgorithm();

        final ASN1ObjectIdentifier oid = algId.getAlgorithm();
        final String pbeAlgorithm = oid.getId();
        final PBEParameter pbeParams = PBEParameter.getInstance(algId.getParameters());
        final byte[] salt = pbeParams.getSalt();
        final int iCount = pbeParams.getIterationCount().intValue();

        final byte[] encryptedData = pInfo.getEncryptedData();

        final PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, iCount);

        final SecretKeyFactory secretKeyFact = SecretKeyFactory.getInstance(pbeAlgorithm, "BC");
        final Cipher cipher = Cipher.getInstance(pbeAlgorithm, "BC");

        cipher.init(Cipher.DECRYPT_MODE, secretKeyFact.generateSecret(pbeKeySpec));
        final byte[] wrappedKey = cipher.doFinal(encryptedData);

        final ASN1InputStream derin = new ASN1InputStream(wrappedKey);
        final PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(derin.readObject());
        derin.close();

        final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        final Key myKey = converter.getPrivateKey(pkInfo);

        return myKey;

    }

    //
    // FILE PARSING CONSTANTS
    //
    private final static String KEY_TAG = "privatekey";
    private final static String CERT_TAG = "certificate";
//    private final static String TRUST_TAG = "certificate"; //commented unused fields

    private final static String KEY_START_PLACEHOLDER = "<slscredentials>";
    private final static String KEY_END_PLACEHOLDER = "</certificatechain>";
    private final static String CERT_START_PLACEHOLDER = "<certificatechain>";
    private final static String CERT_END_PLACEHOLDER = "</certificatechain>";
//    private final static String TRUST_START_PLACEHOLDER = "<trustedcertificates>";
//    private final static String TRUST_END_PLACEHOLDER = "</trustedcertificates>";

    //
    // FILE UTILITY
    //

    /**
     * readXMLfile
     * 
     * @param fileName
     * @return
     */
    private String readXMLfile(final String fileName) {

        if (fileName == null || fileName.equals("")) {
            return null;
        }
        final StringBuffer output = new StringBuffer("");
        String l;
        try {
            final BufferedReader br = new BufferedReader(new FileReader(fileName));
            // store the whole buffer directly into string
            while ((l = br.readLine()) != null) { // while loop begins here
                output.append(l + this.lineFeed);
            } // end while
            br.close();
            return output.toString();

        } catch (final IOException e) {
            return null;
        }
    }

    /**
     * readPemFromXML
     * 
     * @param tag
     * @param startPlaceholder
     * @param endPlaceholder
     * @return
     */
    private String[] readPemFromXML(final String tag, final String startPlaceholder, final String endPlaceholder) {

        final List<String> pemList = new ArrayList<String>();
        boolean lookingFlag = false;
        boolean pickingFlag = false;
        StringBuffer output = null;

        // split the data into lines
        final String[] line = this.xmlStoreData.split(this.lineFeed);
        // search for the zone between startPlaceholder and endPlaceholder
        // inside this zone, for each time we fing the tag, we collect the data and store it
        for (final String l : line) {

            if (lookingFlag && l.trim().contentEquals("</" + tag + ">")) {
                pickingFlag = false;
                // close the gathering for a PEM
                pemList.add(output.toString());
                output = null;
            }

            if (l.trim().contentEquals(endPlaceholder)) {
                lookingFlag = false;
            }

            if (lookingFlag && pickingFlag) {
                // store the PEM line
                output.append(l + this.lineFeed);
            }

            if (lookingFlag && l.trim().contentEquals("<" + tag + ">")) {
                // start a new gathering
                output = new StringBuffer("");
                pickingFlag = true;
            }

            if (l.trim().contentEquals(startPlaceholder)) {
                lookingFlag = true;
            }

        }
        // return the array of PEMs      
        return pemList.toArray(new String[pemList.size()]);

    } // end of addPemToXml

    /**
     * getHexString
     * 
     * @param b
     * @return
     */
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
