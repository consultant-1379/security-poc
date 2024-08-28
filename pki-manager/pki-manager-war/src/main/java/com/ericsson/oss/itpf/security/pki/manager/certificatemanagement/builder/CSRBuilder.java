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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder;

import java.io.IOException;

import javax.inject.Inject;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.util.Constants;

/**
 * This class creates a PKCS10CertificationRequest from the passed data in bytes.
 * 
 * @author tcsvath
 *
 */
public class CSRBuilder {

    @Inject
    private Logger logger;

    /**
     * Creates PKCS10CertificationRequest from the byte array.
     * 
     * @param csrData
     * @return CertificateRequest The CSR containing PKCS10 request.
     * @throws IOException
     *             Thrown in the event of corrupted data, or an incorrect structure.
     */
    public CertificateRequest generateCSR(final String csrData) throws IOException {

        final String csrContent = getCSRContent(csrData);
        logger.debug("CSR Content: {} " , csrContent);

        PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = null;

        final byte[] derByteArray = javax.xml.bind.DatatypeConverter.parseBase64Binary(csrContent);
        final PKCS10CertificationRequest certificationRequest = new PKCS10CertificationRequest(derByteArray);

        final CertificateRequest csr = new CertificateRequest();
        pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(certificationRequest);
        csr.setCertificateRequestHolder(pkcs10CertificationRequestHolder);

        return csr;

    }

    private String getCSRContent(String csrData) {

        final String NEXT_LINE = System.getProperty("file.separator").equals("\\") ? "\n" : "\r\n";
        final String beginCertRequest = Constants.BEGIN_CERTIFICATE_REQUEST;
        final String endCertRequest = Constants.END_CERTIFICATE_REQUEST;

        csrData = csrData.replace(NEXT_LINE, Constants.EMPTY_STRING);
        csrData = csrData.replace(beginCertRequest, Constants.EMPTY_STRING);
        csrData = csrData.replace(endCertRequest, Constants.EMPTY_STRING);
        csrData = csrData.replace(Constants.BEGIN_NEW_CERTIFICATE_REQUEST, Constants.EMPTY_STRING);
        csrData = csrData.replace(Constants.END_NEW_CERTIFICATE_REQUEST, Constants.EMPTY_STRING);
        return csrData;
    }

}
