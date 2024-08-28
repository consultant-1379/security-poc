/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.credmservice.api.rest.model;

import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.annotation.XmlRootElement;

import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;

@XmlRootElement
public class GetCertificateResponse {

    private String[] certificate;

    public String[] getCertificate() {
        return certificate; // NOSONAR
    }

    public void setCertificate(final String[] certificate) {
        this.certificate = certificate;// NOSONAR
    }

    public GetCertificateResponse(final CredentialManagerX509Certificate[] cert) {
        super();
        certificate = new String[cert.length];

        int certsCounter = 0;
        for (final CredentialManagerX509Certificate X509Cert : cert) {
            certificate[certsCounter] = DatatypeConverter.printBase64Binary(X509Cert.getCertBytes());
            certsCounter++;
        }
    }

    public GetCertificateResponse(final int size) {
        super();
        certificate = new String[size];
    }

    public GetCertificateResponse() {
        super();
    }

    @Override
    public String toString() {

        String result = null;
        result = "GetCertificateResponse : ";

        int certsCounter = 0;
        for (final String cert : certificate) {
            result = result + "[certificate n." + certsCounter + 1 + " = " + cert + "]; ";
            certsCounter++;
        }

        return result;
    }
}
