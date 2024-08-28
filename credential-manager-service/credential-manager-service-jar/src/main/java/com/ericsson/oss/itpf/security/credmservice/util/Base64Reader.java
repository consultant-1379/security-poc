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
package com.ericsson.oss.itpf.security.credmservice.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.security.Key;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerStorageException;

/**
 *
 * @author ewagdeb
 *
 */
public class Base64Reader {

    /**
     *
     */
    //private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(Base64Writer.class);

    /**
     * Truststore file Path
     */
    final private String storeFilePath;
    final private String storeFolderPath;

    /**
     * key password
     */
    private String password = "";

    /**
     * .CER file Path
     */
    final private String cerFilePath;

    /**
     * .Key File Path
     */
    final private String privateKeyFilePath;
    private static final Logger log = LoggerFactory.getLogger(Base64Reader.class);

    /**
     * List of Entry contents
     */
    List<X509CertificateHolder> certList = new ArrayList<X509CertificateHolder>();
    List<PrivateKeyInfo> keyList = new ArrayList<PrivateKeyInfo>();
    List<X509CRLHolder> crlList = new ArrayList<X509CRLHolder>();

    public Base64Reader(final String storeFolderPath, final String storeFilePath, final String cerFilePath, final String privateKeyFilePath, final String password) {

        this.storeFilePath = storeFilePath;
        this.storeFolderPath = storeFolderPath;
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
    public Key getPrivateKey(final String alias) throws CredentialManagerStorageException {

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
                throw new CredentialManagerStorageException(e);
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
    public Certificate[] getCertificateChain(final String alias) throws CredentialManagerStorageException {

        this.clearLists();
        // if the folder is indicated, we parse all the files inside
        if (this.storeFolderPath != "") {
            //iterate for each file in the folder
            final File folder = new File(this.storeFolderPath);
            if (folder.exists() && folder.isDirectory()) {
                for (final File file : folder.listFiles()) {
                    this.parseFile(file.getPath());
                }
            }
        } else {
            this.parseFile(this.storeFilePath);
        }

        // it is the get for chain certificate: so we collect all the certificates found
        if (!this.certList.isEmpty()) {
            int i = 0;
            final Certificate[] certArray = new Certificate[this.certList.size()];
            for (final X509CertificateHolder parsed : this.certList) {

                final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
                java.security.cert.X509Certificate x509cert = null;
                try {
                    x509cert = converter.getCertificate(parsed);
                    certArray[i++] = x509cert;
                } catch (final CertificateException e) {
                    throw new CredentialManagerStorageException(e);
                }

            }
            return certArray;
        }
        // it is not a certificate module
        return null;
    }

    /*
     * getCertificate
     * 
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#getCertificate(java.lang.String)
     */
    public Certificate getCertificate(final String alias) throws CredentialManagerStorageException {

        this.clearLists();
        if (this.cerFilePath != "") {
            this.parseFile(this.cerFilePath);
        } else {
            this.parseFile(this.storeFilePath);
        }

        if (!this.certList.isEmpty()) {
            final X509CertificateHolder parsed = this.certList.get(0);

            final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            java.security.cert.X509Certificate x509cert = null;
            try {
                x509cert = converter.getCertificate(parsed);
            } catch (final CertificateException e) {
                throw new CredentialManagerStorageException(e);
            }
            return x509cert;
        }
        // it is not a certificate module
        return null;
    }

    // TODO add this to credentialreader interface
    /**
     * getCRL
     *
     * @param alias
     * @return
     * @throws CredentialManagerStorageException
     */
    public CRL getCRL(final String alias) throws CredentialManagerStorageException {

        this.clearLists();
        this.parseFile(this.storeFilePath);

        if (!this.crlList.isEmpty()) {
            final X509CRLHolder parsed = this.crlList.get(0);

            final JcaX509CRLConverter converter = new JcaX509CRLConverter();
            java.security.cert.CRL crl = null;
            try {
                crl = converter.getCRL(parsed);
            } catch (final CRLException e) {
                throw new CredentialManagerStorageException(e);
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
     * @throws CredentialManagerStorageException
     */
    private void parseFile(final String filename) throws CredentialManagerStorageException {

        PEMParser pp = null;

        // buffer where to store the lines read form the file
        StringBuffer pemBuf = new StringBuffer();

        // the PEM file is a text file, we open it as simple text
        InputStream fis;
        try {
            fis = new FileInputStream(filename);
        } catch (final FileNotFoundException e) {
            throw new CredentialManagerStorageException(e);
        }
        final InputStreamReader isr = new InputStreamReader(fis);
        final BufferedReader br = new BufferedReader(isr);
        String line;
        try {
            // collect all the lines read from the file until we find one containing END
            // at this point we have in stringbuffer and entire entry from the "BEGIN" line to the "END" one
            // (of any type: key, certificate... we dont know yet)
            while ((line = br.readLine()) != null) {
                pemBuf.append(line);
                pemBuf.append(System.getProperty("line.separator"));
                if (line.startsWith("-----END")) {

                    //parse an entry in the PEM file
                    final StringReader entryReader = new StringReader(pemBuf.toString());
                    pp = new PEMParser(entryReader);

                    // the parser will add the content to the right list
                    this.parseEntry(pp);

                    // clear buffer (to start a new iteration)
                    pemBuf = new StringBuffer();
                }
            }
        } catch (final IOException e) {
            throw new CredentialManagerStorageException(e);
        } finally {
            try {
                br.close();
            } catch (IOException e) {
                log.debug("parseFile exception {}", e);
                throw new CredentialManagerStorageException(e);
            }
        }
    }

    /**
     * parseEntry
     *
     * @param pe
     * @throws CredentialManagerStorageException
     */
    private void parseEntry(final PEMParser pe) throws CredentialManagerStorageException {

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

        // the entry is an encrypted keypair
        if (obj instanceof PEMEncryptedKeyPair) {
            // decrypt it and store it in keyList
            PEMKeyPair decryptedKeyPair;
            try {
                final PEMDecryptorProvider decryptionProv = new JcePEMDecryptorProviderBuilder().build(this.password.toCharArray());
                decryptedKeyPair = ((PEMEncryptedKeyPair) obj).decryptKeyPair(decryptionProv);
                this.keyList.add(decryptedKeyPair.getPrivateKeyInfo());
            } catch (final IOException e) {
                throw new CredentialManagerStorageException(e);
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

}
