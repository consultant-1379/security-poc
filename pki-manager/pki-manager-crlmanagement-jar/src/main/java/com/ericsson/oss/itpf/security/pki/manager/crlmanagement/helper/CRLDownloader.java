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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.helper;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class CRLDownloader {
	private static final Logger log = LoggerFactory.getLogger(CRLDownloader.class);
	private CRLDownloader() {}
    public static X509CRL getCRLFromURL(final URL url) throws CRLException {

        InputStream crlFile = null;
        X509CRL x509CRL = null;

        try {

        	final HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
            httpConn.setRequestMethod("GET");
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);

            final int responseCode = httpConn.getResponseCode();

            // always check HTTP response code first
            if (responseCode == HttpURLConnection.HTTP_OK) {
                crlFile = httpConn.getInputStream();
                if (crlFile != null) {
                    final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    x509CRL = (X509CRL) certificateFactory.generateCRL(crlFile);
                }
            } else {
            	final String msg = "ERROR downloading CRL from: " + url + " HTTP response code: " + responseCode;
            	log.error(msg);
            	throw new CRLException(msg);
            }
        } catch (IOException e) {
        	log.error("ERROR opening HTTP connection");
            throw new CRLException(e);
        } catch (CertificateException e) {
			log.error("ERROR parsing CRL");
			throw new CRLException(e);
		}
        return x509CRL;
    }

	
	
}
