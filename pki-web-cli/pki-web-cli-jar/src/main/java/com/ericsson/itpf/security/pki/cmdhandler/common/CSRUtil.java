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
package com.ericsson.itpf.security.pki.cmdhandler.common;

import java.io.IOException;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;

/**
 * Util class to generate the CSR based on the input csrData that is read from
 * file
 * 
 * @author xpranma
 * 
 */

// TODO: This class has to be moved to pki-common repository once it is created. Implementing CSR related code here with
// reference to TORF-53695

public abstract class CSRUtil {

    private CSRUtil() {
        throw new IllegalStateException("CSRUtil class");
    }

    /**
     * Method to generate CSR based on the csrData that is read from the input
     * CSR file
     * 
     * @param csrData
     * @return
     * @throws IOException
     *             if input content is not proper and its failed to read the
     *             content
     */
    public static CertificateRequest generateCSR(final String csrData) throws IOException {

        final String csrContent = getCSRContent(csrData);

        AbstractCertificateRequestHolder pkcs10CertificationRequestHolder = null;

        final byte[] derByteArray = javax.xml.bind.DatatypeConverter.parseBase64Binary(csrContent);
        final PKCS10CertificationRequest certificationRequest = new PKCS10CertificationRequest(derByteArray);

        final CertificateRequest csr = new CertificateRequest();
        pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(certificationRequest);
        csr.setCertificateRequestHolder(pkcs10CertificationRequestHolder);

        return csr;

    }

    private static String getCSRContent(String csrData) {

        String csrDataInput = csrData;
        csrDataInput = csrDataInput.replace(Constants.BEGIN_CERTIFICATE_REQUEST, Constants.EMPTY_STRING);
        csrDataInput = csrDataInput.replace(Constants.END_CERTIFICATE_REQUEST, Constants.EMPTY_STRING);
        csrDataInput = csrDataInput.replace(Constants.BEGIN_NEW_CERTIFICATE_REQUEST, Constants.EMPTY_STRING);
        csrDataInput = csrDataInput.replace(Constants.END_NEW_CERTIFICATE_REQUEST, Constants.EMPTY_STRING);
        return csrDataInput;
    }

    /**
     * To get CommonName from CSR data
     * @param certificateRequest
     *            the PKCS10/CRMF request
     * @return Common Name in CSR
     * @throws InvalidCertificateRequestException
     *             thrown incase of Common Name not found in csrData
     * @throws IOException
     *             thrown incase of i/o failure
     */
    public static String getCNFromCSR(final CertificateRequest certificateRequest) throws InvalidCertificateRequestException, IOException {

        X500Name x500NameSubject = null;

        if (certificateRequest.getCertificateRequestHolder() != null) {

            if (certificateRequest.getCertificateRequestHolder() instanceof PKCS10CertificationRequestHolder) {
                final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = (PKCS10CertificationRequestHolder) certificateRequest
                        .getCertificateRequestHolder();
                final PKCS10CertificationRequest pkcs10CertificationRequest = pkcs10CertificationRequestHolder.getCertificateRequest();
                x500NameSubject = pkcs10CertificationRequest.getSubject();
            } else {
                final CRMFRequestHolder crmfRequestHolder = (CRMFRequestHolder) certificateRequest.getCertificateRequestHolder();
                final CertificateRequestMessage crmfCertificationRequest = crmfRequestHolder.getCertificateRequest();
                x500NameSubject = crmfCertificationRequest.getCertTemplate().getSubject();
            }

        } else {
            throw new InvalidCertificateRequestException("Invalid CSR");
        }

        final RDN[] commonNameRDNs = x500NameSubject.getRDNs(BCStyle.CN);
        if (commonNameRDNs.length > 0) {
            final RDN commonName = commonNameRDNs[0];
            return commonName.getFirst().getValue().toString();
        } else {
            throw new InvalidCertificateRequestException("Invalid Subject in CSR");
        }
    }
}
