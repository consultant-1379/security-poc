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
package com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml;

import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;

/**
 * This class is used to get the XML Signer Public Key information from the KeyInfo object which have been prepared from Signed XML. Based on the Signer Public Key Algorithm, it will identify the
 * algorithms to verify the Signature on the XML.
 * 
 * @author tcschdy
 *
 */
public class X509KeySelector extends KeySelector {

    public KeySelectorResult select(final KeyInfo keyInfo, final KeySelector.Purpose purpose, final AlgorithmMethod method, final XMLCryptoContext context) throws KeySelectorException {
        final Iterator<?> keyInfoIterator = keyInfo.getContent().iterator();
        while (keyInfoIterator.hasNext()) {
            final XMLStructure xMLStructure = (XMLStructure) keyInfoIterator.next();
            if (!(xMLStructure instanceof X509Data)) {
                continue;
            }

            final X509Data x509Data = (X509Data) xMLStructure;
            final Iterator<?> x509CertificateIterator = x509Data.getContent().iterator();
            while (x509CertificateIterator.hasNext()) {
                final Object object = x509CertificateIterator.next();
                if (!(object instanceof X509Certificate)) {
                    continue;
                }

                final PublicKey key = ((X509Certificate) object).getPublicKey();

                if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
                    return new KeySelectorResult() {
                        public Key getKey() {
                            return key;
                        }
                    };
                }
            }
        }
        throw new KeySelectorException("No key found!");
    }

    private static boolean algEquals(final String algorithmURI, final String algorithmName) {
        boolean isEqual = false;
        if ((algorithmName.equalsIgnoreCase(Constants.DSA_ALGORITHM) && algorithmURI.equalsIgnoreCase(Constants.DSA_ALGORITHM_URI))
                || (algorithmName.equalsIgnoreCase(Constants.RSA_ALGORITHM) && algorithmURI.equalsIgnoreCase(Constants.RSA_ALGORITHM_URI))) {
            isEqual = true;
        }
        return isEqual;
    }
}
