/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;

public class Base64Reader {
    List<X509CertificateHolder> certList = new ArrayList<X509CertificateHolder>();
    List<PrivateKeyInfo> keyList = new ArrayList<PrivateKeyInfo>();

    /*
     * getCertificate
     *
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader#getCertificate(java.lang.String)
     */
    public Certificate getCertificate(final InputStream fis) throws CertificateException, CertificateNotFoundException{

        this.keyList.clear();
        this.certList.clear();
        this.parseFile(fis);

        if (!this.certList.isEmpty()) {
            if (this.certList.size() > 1) {
                throw new CertificateException(ErrorMessages.PEM_WITH_MORE_CERTIFICATES);
            }
            final X509CertificateHolder parsed = this.certList.get(0);

            final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            java.security.cert.X509Certificate x509cert = null;
            try {
                x509cert = converter.getCertificate(parsed);
            } catch (final  java.security.cert.CertificateException e) {
                throw new CertificateNotFoundException(e);
            }
            return x509cert;
        }
        // it is not a certificate module
        return null;
    }


    /**
     * fileParsing
     *
     * @param filename
     * @throws CertificateException
     * @throws StorageException
     */
    private void parseFile(final InputStream fis) throws CertificateException  {
        PEMParser pp = null;

        // buffer where to store the lines read form the file
        StringBuilder pemBuf = new StringBuilder();

        // the PEM file is a text file, we open it as simple text
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
    private void parseEntry(final PEMParser pe) throws CertificateException, IOException {

        final Object obj = pe.readObject();
        pe.close();

        if (obj instanceof PEMKeyPair) {
            final PrivateKeyInfo myKey = ((PEMKeyPair) obj).getPrivateKeyInfo();
            this.keyList.add(myKey);

            // the entry is a certificate
        } else if (obj instanceof X509CertificateHolder) {
            this.certList.add((X509CertificateHolder) obj);
        }
    }

} // end of Base64Reader