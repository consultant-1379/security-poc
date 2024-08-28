/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.api.model;


import java.io.Serializable;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;

/**
 * Certificate authority or certification authority (CA), is an entity that
 * issues digital certificates.
 * 
 * The digital certificate certifies the ownership of a public key by the named
 * subject of the certificate.
 * 
 * This allows others (relying parties) to rely upon signatures or assertions
 * made by the private key that corresponds to the public key that is certified.
 * 
 * @author egbobcs
 */
public class CredentialManagerCertificateAuthority implements Serializable {

    private static final long serialVersionUID = -9186061169648614728L;

    protected String simpleName;

    List<CredentialManagerX509Certificate> certChainSerializable = new ArrayList<CredentialManagerX509Certificate>();

    public CredentialManagerCertificateAuthority(final CredentialManagerCertificateAuthority other) {
        this.simpleName = other.getSimpleName();
        this.certChainSerializable = new ArrayList<>(other.getCertChainSerializable());
    }

    public CredentialManagerCertificateAuthority(final String name) {
        this.simpleName = name;
    }

    public CredentialManagerCertificateAuthority(final X500Name name, final String simpleName) {
        this.simpleName = simpleName;
    }

    public String getSimpleName() {
        return simpleName;
    }

    public List<CredentialManagerX509Certificate> getCACertificateChain() {

        return certChainSerializable;
    }

    @Override
    public String toString() {
        String ret = "CertificateAuthority: ";
        ret += simpleName;
        return ret;
    }

    public void add(final X509Certificate cert) throws CertificateEncodingException {
        this.certChainSerializable.add(new CredentialManagerX509Certificate(cert));
        //initCertChain();
    }

    //    public CredentialManagerX509Certificate signCertificateRequest(final CredentialManagerPKCS10CertRequest request)
    //            throws CredentialManagerException {
    //        throw new CredentialManagerException("Fail to sign Certificate");
    //    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + simpleName.hashCode();
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

        return true;
    }

    public List<CredentialManagerX509Certificate> getCertChainSerializable() {
        return certChainSerializable;
    }

    public void setCertChainSerializable(final List<CredentialManagerX509Certificate> certChainSerializable) {
        this.certChainSerializable = certChainSerializable;
    }

}
