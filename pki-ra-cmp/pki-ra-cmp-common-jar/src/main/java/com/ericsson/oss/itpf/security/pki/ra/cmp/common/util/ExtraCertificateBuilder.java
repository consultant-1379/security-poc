/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.cmp.common.util;

import java.io.IOException;
import java.security.cert.*;
import java.util.*;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cmp.CMPCertificate;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.ResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;

/**
 * The purpose of this class is to have utility methods which will build extraCertificates to be sent to the entity. Method:
 * <code> buildExtraCertList(final List<X509Certificate> signerCertificateChain, final ResponseMessage responsePKIMessage) throws CertificateException, IOException </code><br>
 * will return a List of X509Certificates which can be directly used in response building.
 *
 * @author tcsdemi
 *
 */
public class ExtraCertificateBuilder {

    private ExtraCertificateBuilder() {

    }

    /**
     * This method adds cumulatively all the certificates which are present in the requestMessage with RA signer certificate and its chain and return a Set of X509 certificates. While adding this
     * method also check if there are any duplicate certificates, if yes then these certificates are discarded and not added into the set.
     *
     * @param signerCertificateChain
     *            This is the RA certificateChain till RootCA
     * @param responsePKIMessage
     *            When responseMessage is built it contains generated user-certificate and its Chain till root CA
     * @return
     * @throws CertificateException
     *             This exception is thrown in case there is an parsing exception which converting CMPCertificate into X509Certificate.
     *
     * @throws IOException
     *             This exception is thrown while returning BER/DER encoding of the certificate.
     */
    public static List<X509Certificate> buildExtraCertList(final List<X509Certificate> signerCertificateChain, final ResponseMessage responsePKIMessage) throws CertificateException, IOException {

        List<X509Certificate> certificatesWithRAChain = null;
        final CMPCertificate[] cMPCertificates = responsePKIMessage.getPKIResponseMessage().getExtraCerts();
        if (cMPCertificates != null) {
            certificatesWithRAChain = convertCMPCertToX509(cMPCertificates, signerCertificateChain);
        } else {
            certificatesWithRAChain = signerCertificateChain;
        }
        return certificatesWithRAChain;
    }

    private static List<X509Certificate> convertCMPCertToX509(final CMPCertificate[] extraCerts, final List<X509Certificate> signerCertificateChain) throws CertificateException, IOException {

        final List<X509Certificate> certificatesWithRAChain = new ArrayList<>(signerCertificateChain);

        if (extraCerts != null) {
            for (final CMPCertificate eachCert : extraCerts) {
                if (eachCert.isX509v3PKCert()) {
                    final X509Certificate x509Certificate = (X509Certificate) CertificateFactory.getInstance(Constants.X509).generateCertificate(new ASN1InputStream(eachCert.getEncoded()));
                    final boolean isPresent = resolveDuplicateCerts(certificatesWithRAChain, x509Certificate);
                    if (!isPresent) {
                        certificatesWithRAChain.add(x509Certificate);
                    }
                }
            }
        }
        return certificatesWithRAChain;
    }

    private static boolean resolveDuplicateCerts(final List<X509Certificate> extraCertsList, final X509Certificate x509Certificate) {

        boolean isExists = false;
        final Iterator<X509Certificate> extraCertsItr = extraCertsList.iterator();
        final String existingIssuer = CertificateUtility.getSubjectName(x509Certificate);
        final String existingSerialNo = x509Certificate.getSerialNumber().toString();

        while (extraCertsItr.hasNext()) {
            final X509Certificate x509CertificateFromChain = extraCertsItr.next();
            final String issuerNameFromChain = CertificateUtility.getSubjectName(x509CertificateFromChain);
            final String serialNumberFromchain = x509CertificateFromChain.getSerialNumber().toString();
            if (issuerNameFromChain.equalsIgnoreCase(existingIssuer) && serialNumberFromchain.equalsIgnoreCase(existingSerialNo)) {
                isExists = true;
                break;
            }
        }
        return isExists;
    }

}
