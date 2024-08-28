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

import java.io.IOException;

import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.annotation.XmlRootElement;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

@XmlRootElement
public class GetCertificateRequest {

    private String csrEncoded;
    private String password;

    public GetCertificateRequest(final PKCS10CertificationRequest csr) {
        super();
        try {
            csrEncoded = DatatypeConverter.printBase64Binary(csr.getEncoded());
        } catch (final IOException e) { //NOSONAR
            e.printStackTrace();
        }
    }

    public GetCertificateRequest() {
        super();
    }

    public String getCsrEncoded() {
        return csrEncoded;
    }

    public void setCsrEncoded(final String csrEncoded) {
        this.csrEncoded = csrEncoded;
    }

    @Override
    public String toString() {
        return "GetCertificateRequest [csrHolder=" + csrEncoded + "]";
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(final String password) {
        this.password = password;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (csrEncoded == null ? 0 : csrEncoded.hashCode());
        result = prime * result + (password == null ? 0 : password.hashCode());
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final GetCertificateRequest other = (GetCertificateRequest) obj;
        if (csrEncoded == null) {
            if (other.csrEncoded != null) {
                return false;
            }
        } else if (!csrEncoded.equals(other.csrEncoded)) {
            return false;
        }
        if (password == null) {
            if (other.password != null) {
                return false;
            }
        } else if (!password.equals(other.password)) {
            return false;
        }
        return true;
    }
}
