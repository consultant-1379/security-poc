/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util;

import java.io.*;
import java.security.Key;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;


/**
 *
 * @author ewagdeb
 *
 */
public class Base64Reader {

   // private final static Logger LOG = LoggerFactory.getLogger(Base64Reader.class);
    /**
     *
     */
    //private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(Base64Writer.class);

    /**
     * Truststore file Path
     */
    private String storeFilePath = "";
    /**
     * key password
     */
    private String password = "";

    /**
     * .CER file Path
     */
    private String cerFilePath = "";

    /**
     * .Key File Path
     */
    private String privateKeyFilePath = "";

    /**
     * List of Entry contents
     */
    List<X509CertificateHolder> certList = new ArrayList<>();
    List<PrivateKeyInfo> keyList = new ArrayList<>();
    List<X509CRLHolder> crlList = new ArrayList<>();

    private Base64Reader() {

    }

    public Base64Reader(final String storeFolderPath, final String storeFilePath, final String cerFilePath, final String privateKeyFilePath, final String password) {
        this.storeFilePath = storeFilePath;
        this.cerFilePath = cerFilePath;
        this.privateKeyFilePath = privateKeyFilePath;
        if (password != null && !password.trim().equals("")) {
            this.password = password;
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#getPrivateKey(java.lang.String)
     */
    public Key getPrivateKey() throws CertificateException{

        this.clearLists();
        if (this.privateKeyFilePath != "") {
            this.parseFile(this.privateKeyFilePath);
        } else {
            this.parseFile(this.storeFilePath);
        }

        if (!this.keyList.isEmpty()) {
            final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            Key myKey;
            try {
                myKey = converter.getPrivateKey(this.keyList.get(0));
            } catch (final PEMException e) {
                throw new CertificateException(e);
            }
            return myKey;
        }
        // it is not a key module
        return null;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#getCertificateChain(java.lang.String)
     */
    /*
     * getCertificate
     *
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#getCertificate(java.lang.String)
     */
    public Certificate getCertificate(final String alias) throws CertificateException, CertificateNotFoundException{

        this.clearLists();
        if (this.cerFilePath != "") {
            this.parseFile(this.cerFilePath);
        } else {
            this.parseFile(this.storeFilePath);
        }

        if (!this.certList.isEmpty()) {
            if (this.certList.size() > 1) {
                throw new CertificateException();
            }
            final X509CertificateHolder parsed = this.certList.get(0);

            final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            java.security.cert.X509Certificate x509cert = null;
            try {
                x509cert = converter.getCertificate(parsed);
            } catch (final  java.security.cert.CertificateException e) {
                throw new CertificateNotFoundException();
            }
            return x509cert;
        }
        // it is not a certificate module
        return null;
    }

    /**
     * getCRL
     *
     * @return
     * @throws CertificateException
     * @throws StorageException
     */
    public CRL getCRL() throws CertificateException{

        this.clearLists();
        this.parseFile(this.storeFilePath);

        if (!this.crlList.isEmpty()) {
            final X509CRLHolder parsed = this.crlList.get(0);

            final JcaX509CRLConverter converter = new JcaX509CRLConverter();
            java.security.cert.CRL crl = null;
            try {
                crl = converter.getCRL(parsed);
            } catch (final CRLException e) {
                throw new CertificateException(e);
            }
            return crl;
        }
        // it is not a crl module
        return null;
    }

    //
    // FILE PARSING
    //

    /**
     * fileParsing
     *
     * @param filename
     * @throws CertificateException
     * @throws StorageException
     */
    private void parseFile(final String filename) throws CertificateException{

        PEMParser pp = null;
        // buffer where to store the lines read form the file
        StringBuilder pemBuf = new StringBuilder();

        // the PEM file is a text file, we open it as simple text

        String line;
        try (InputStream fis = new FileInputStream(filename);
                InputStreamReader isr = new InputStreamReader(fis);
                BufferedReader br = new BufferedReader(isr);) {
            // collect all the lines read from the file until we find one
            // containing END
            // at this point we have in stringbuffer and entire entry from the
            // "BEGIN" line to the "END" one
            // (of any type: key, certificate... we dont know yet)
            while ((line = br.readLine()) != null) {
                // System.out.println("line : " + line);
                pemBuf.append(line);
                pemBuf.append(System.getProperty("line.separator"));
                if (line.startsWith("-----END")) {

                    // parse an entry in the PEM file
                    final StringReader entryReader = new StringReader(pemBuf.toString());
                    pp = new PEMParser(entryReader);

                    // the parser will add the content to the right list
                    this.parseEntry(pp);

                    // clear buffer (to start a new iteration)
                    pemBuf = new StringBuilder();
                }
            }
        } catch (final IOException e) {
            throw new CertificateException(e);
        }
    }

    /**
     * parseEntry
     *
     * @param pe
     * @throws CertificateException
     * @throws StorageException
     */
    private void parseEntry(final PEMParser pe) throws CertificateException {

        Object obj = null;
        try {
            obj = pe.readObject();
            pe.close();
        } catch (final IOException e) {
            // caught exception, its ok if the entry is not readable,
            // we can be in a case where multiple files ore reading
            // just collect the right ones
            //throw new StorageException(e);
        }
        //System.out.println("PEM object : "+obj.getClass().toString());

        // the entry is an encrypted keypair
        if (obj instanceof PEMEncryptedKeyPair) {
            // decrypt it and store it in keyList
            PEMKeyPair decryptedKeyPair;
            try {
                final PEMDecryptorProvider decryptionProv = new JcePEMDecryptorProviderBuilder().build(this.password.toCharArray());
                decryptedKeyPair = ((PEMEncryptedKeyPair) obj).decryptKeyPair(decryptionProv);
                this.keyList.add(decryptedKeyPair.getPrivateKeyInfo());
            } catch (final IOException e) {
                throw new CertificateException(e);
            }
            //this.keyList.add(decryptedKeyPair);

            // the entry is a keypair
        } else if (obj instanceof PEMKeyPair) {
            final PrivateKeyInfo myKey = ((PEMKeyPair) obj).getPrivateKeyInfo();
            this.keyList.add(myKey);

            // the entry is a certificate
        } else if (obj instanceof X509CertificateHolder) {
            this.certList.add((X509CertificateHolder) obj);

            // the entry is a CRL
        } else if (obj instanceof X509CRLHolder) {
            this.crlList.add((X509CRLHolder) obj);
        }

    }

    /**
     * clearList
     */
    private void clearLists() {
        this.keyList.clear();
        this.certList.clear();
        this.crlList.clear();
    }


} // end of Base64Reader
