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
package com.ericsson.oss.itpf.security.credmsapi.storage.business;

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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;

/**
 * 
 * @author ewagdeb
 * 
 */
public class Base64Reader implements CredentialReader {

    private static final Logger LOG = LogManager.getLogger(Base64Reader.class);
    /**
     * 
     */
    //private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(Base64Writer.class);

    /**
     * Truststore file Path
     */
    private String storeFilePath = "";
    private String storeFolderPath = "";

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
    List<X509CertificateHolder> certList = new ArrayList<X509CertificateHolder>();
    List<PrivateKeyInfo> keyList = new ArrayList<PrivateKeyInfo>();
    List<X509CRLHolder> crlList = new ArrayList<X509CRLHolder>();

    @SuppressWarnings("unused")
    private Base64Reader() {

    }

    public Base64Reader(final String storeFolderPath, final String storeFilePath, final String cerFilePath, final String privateKeyFilePath, final String password) {

        if (storeFilePath != null) {
            this.storeFilePath = storeFilePath;
        }
        if (storeFolderPath != null) {
            this.storeFolderPath = storeFolderPath;
        }
        if (cerFilePath != null) {
            this.cerFilePath = cerFilePath;
        }
        if (privateKeyFilePath != null) {
            this.privateKeyFilePath = privateKeyFilePath;
        }
        if (password != null && !password.trim().equals("")) {
            this.password = password;
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#getPrivateKey(java.lang.String)
     */
    @Override
    public Key getPrivateKey(final String alias) throws StorageException {

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
                LOG.error(ErrorMsg.API_ERROR_STORAGE_CONVERT_PRIVATEKEY, alias);
                throw new StorageException(e);
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
    @Override
    public Certificate[] getCertificateChain(final String alias) throws StorageException {

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
        } else if (this.storeFilePath != "") {
            this.parseFile(this.storeFilePath);
        } else {
            this.parseFile(this.cerFilePath);
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
                    LOG.error(ErrorMsg.API_ERROR_STORAGE_CONVERT_CERT, alias);
                    throw new StorageException(e);
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
    @Override
    public Certificate getCertificate(final String alias) throws StorageException {

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
                LOG.error(ErrorMsg.API_ERROR_STORAGE_CONVERT_CERT, alias);
                throw new StorageException(e);
            }
            return x509cert;
        }
        // it is not a certificate module
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#getAllCertificates()
     */
    @Override
    public Set<Certificate> getAllCertificates(final String rootAlias) throws StorageException {
        final Certificate[] certs = this.getCertificateChain(rootAlias); //It doesnt show anything which selects only some alias
        final Set<Certificate> certificates = new HashSet<Certificate>();
        if (certs != null) { // null is acceptable, it means there is no certificates
            for (final Certificate cert : certs) {
                certificates.add(cert);
            }
        }
        return certificates;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#getCRLs(java.lang.String)
     */
    @Override
    public Set<CRL> getCRLs(final String alias) throws StorageException {

        final Set<CRL> crlSet = new HashSet<CRL>();

        // retrieve all the CRLS
        this.clearLists();
        // if the folder is indicated, we parse all the files inside
        if (this.storeFolderPath != "") {
            //iterate for each file in the folder
            final File folder = new File(this.storeFolderPath);
            if (folder.exists() && folder.isDirectory()) {
                for (final File file : folder.listFiles()) {
                    if (alias != null && alias != "" && file.getName().startsWith(alias)) {
                        this.parseFile(file.getPath());
                    }
                }
            }
        } else {
            this.parseFile(this.storeFilePath);
        }

        //gather them 
        if (!this.crlList.isEmpty()) {
            for (int index = 0; index < this.crlList.size(); index++) {
                crlSet.add(this.getCRL(index));
            }
        }

        return crlSet;
    }

    /**
     * getCRL
     * 
     * @param crlIndex
     * @return
     * @throws StorageException
     */
    private CRL getCRL(final int crlIndex) throws StorageException {

        final X509CRLHolder parsed = this.crlList.get(crlIndex);
        //extract CRL from holder
        final JcaX509CRLConverter converter = new JcaX509CRLConverter();

        java.security.cert.CRL crl = null;
        try {
            crl = converter.getCRL(parsed);
        } catch (final CRLException e) {
            LOG.error(ErrorMsg.API_ERROR_STORAGE_CONVERT_CRLENTRY);
            throw new StorageException(e);
        }
        return crl;
    }

    //
    // FILE PARSING
    //

    /**
     * fileParsing
     * 
     * @param filename
     * @throws StorageException
     */
    private void parseFile(final String filename) throws StorageException {

        PEMParser pp = null;

        // buffer where to store the lines read form the file
        StringBuffer pemBuf = new StringBuffer();

        // the PEM file is a text file, we open it as simple text
        InputStream fis;
        try {
            fis = new FileInputStream(filename);
        } catch (final FileNotFoundException e) {
            LOG.debug("File not found:" + filename);
            // file not found, simply do nothing
            return;
        }
        final InputStreamReader isr = new InputStreamReader(fis);
        final BufferedReader br = new BufferedReader(isr);
        String line;
        try {
            // collect all the lines read from the file until we find one containing END
            // at this point we have in stringbuffer and entire entry from the "BEGIN" line to the "END" one
            // (of any type: key, certificate... we dont know yet) 
            while ((line = br.readLine()) != null) {
                //System.out.println("line : " + line);
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
            throw new StorageException(e);
        } finally {
            try {
                br.close();
            } catch (IOException e) {
                LOG.error(ErrorMsg.API_ERROR_STORAGE_CLOSE_INPUTSTREAM,filename);
            }
        }
    }

    /**
     * parseEntry
     * 
     * @param pe
     * @throws StorageException
     */
    private void parseEntry(final PEMParser pe) throws StorageException {

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
                LOG.error(ErrorMsg.API_ERROR_STORAGE_ADD_PRIVATEKEY);
                throw new StorageException(e);
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

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#hasMoreEntries()
     */
    //    @Override
    //    public boolean hasMoreEntries() throws StorageException {
    //        // TODO Auto-generated method stub
    //        return false;
    //    }

    //    public CRL readCRL(final  String crlfilename) throws StorageException {
    //
    //        Reader fis = null;
    //        org.bouncycastle.openssl.PEMReader pr = null;
    //
    //        StringBuffer pemBuf=new StringBuffer();
    //        
    //        try {
    //
    //            
    //            fis = new FileReader(crlfilename);
    //            pr = new org.bouncycastle.openssl.PEMReader(fis);
    //            //Object obj = pr.readObject();
    //            //System.out.println("CRL obj class : "+obj.getClass().toString());
    //            String line;
    //            while ((line = pr.readLine()) != null) {
    //                System.out.println("CRL line : "+line);
    //                if (line.equals("-----BEGIN CRL-----") || line.equals("-----BEGIN X509 CRL-----")) {
    //                    continue;
    //                }
    //                if (line.equals("-----END CRL-----") || line.equals("-----END X509 CRL-----")) {
    //                    continue;
    //                }
    //                pemBuf.append(line);
    //            }
    //
    //            if (pemBuf.length() != 0) {
    //                ByteArrayInputStream bIn=new ByteArrayInputStream(Base64.decode(pemBuf.toString()));
    //                CRL crl = readDERCRL(bIn);
    //                
    //                System.out.println("CRL = : "+crl.getType());
    //                
    //                return crl;
    //              }
    //
    //            
    ////            try {
    ////                final File file = new File(myStoreFilePath);
    ////                if (!file.exists()) {
    ////                    file.createNewFile();
    ////                }
    ////            } catch (final Exception e) {
    ////
    ////            }
    ////            fos = new FileWriter(new File(myStoreFilePath), true);
    ////            pw = new org.bouncycastle.openssl.PEMWriter(fos);
    ////            pw.writeObject(cert);
    ////            pw.flush();
    //
    //            //            LOG.info(Logger.getLogMessage(Logger.LOG_INFO_CREATE_END_TRUSTSTORE), storeFilePath);
    //            //            LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_CREATE_TRUSTSTORE), storeFilePath);
    //
    //        } catch (final Exception ex) {
    //            return null;
    //        }
    //        return null;
    //    }

    //
    // UTILITY TO READ AND DECODE A PEM FILE
    //

    //    private ASN1Set     sData = null;
    //    private int         sDataObjectCount = 0;
    //    
    //    private CRL readDERCRL(
    //            InputStream in)
    //            throws IOException, CRLException
    //        {
    //            //ASN1InputStream dIn = new ASN1InputStream(in, ProviderUtil.getReadLimit(in));
    //            ASN1InputStream dIn = new ASN1InputStream(in);
    //            ASN1Sequence seq = (ASN1Sequence)dIn.readObject();
    //
    //            if (seq.size() > 1
    //                    && seq.getObjectAt(0) instanceof DERObjectIdentifier)
    //            {
    //                if (seq.getObjectAt(0).equals(PKCSObjectIdentifiers.signedData))
    //                {
    //                    sData = new SignedData(ASN1Sequence.getInstance(
    //                                    (ASN1TaggedObject)seq.getObjectAt(1), true)).getCRLs();
    //
    //                    return getCRL();
    //                }
    //            }
    //
    //            return new X509CRLObject(CertificateList.getInstance(seq));
    //        }
    //    
    //    private CRL getCRL()
    //            throws CRLException
    //        {
    //            if (sData == null || sDataObjectCount >= sData.size())
    //            {
    //                return null;
    //            }
    //
    //            return new X509CRLObject(
    //                            CertificateList.getInstance(
    //                                    sData.getObjectAt(sDataObjectCount++)));
    //        }
    //

} // end of Base64Reader
