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
package com.ericsson.oss.itpf.security.credmsapi.api.model;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.X509Extensions;

import com.ericsson.oss.itpf.security.credmsapi.business.utils.CredentialManagerSubjectAlternateNameImpl;

/**
 * 
 * The class hold the Attributes of Certificate Extension
 * 
 */
public class CredentialManagerCertificateExtensionImpl implements CredentialManagerCertificateExtension {

    /**
     * 
     */
    private static final long serialVersionUID = 2347119582899529848L;
    private Map<String, Attribute> attributes;
    private String subjectAlternativeName;

    /**
     * @param
     */
    public CredentialManagerCertificateExtensionImpl() {
        super();
    }

    /**
     * @param attributes
     * @param subjectAlternativeName
     */
    public CredentialManagerCertificateExtensionImpl(final Map<String, Attribute> attributes, final String subjectAlternativeName) {
        super();
        this.attributes = attributes;
        this.subjectAlternativeName = subjectAlternativeName;
    }

    /**
     * @param CertificateExtensionType
     */
    public CredentialManagerCertificateExtensionImpl(final Object certificateextensionObj) {
        CertificateExtensionType certificateextension = null;

        if (certificateextensionObj != null && certificateextensionObj instanceof CertificateExtensionType) {
            certificateextension = (CertificateExtensionType) certificateextensionObj;

        }

        if (certificateextension != null) {
            final SubjectAlternativeNameType subjectAltName = certificateextension.getSubjectalternativename();
            final CredentialManagerSubjectAlternateNameImpl credMsubjAltName = new CredentialManagerSubjectAlternateNameImpl(subjectAltName);
            attributes = new HashMap<String, Attribute>();
            subjectAlternativeName = credMsubjAltName.getSubjectAlternativeName();
            attributes.put(X509Extensions.SubjectAlternativeName.toString(), credMsubjAltName.getAttribute());
        }

    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.pki.model. CredentialManagerCertificateExtension#getAttributes()
     */
    @Override
    public Map<String, Attribute> getAttributes() {
        return attributes;
    }

    @Override
    public String getSubjectAlternativeName() {
        return subjectAlternativeName;
    }

    /**
     * @param attributes
     *            the attributes to set
     */
    @Override
    public void setAttributes(final Map<String, Attribute> attributes) {
        this.attributes = attributes;
    }

    /**
     * @param subjectAlternativeName
     *            the subjectAlternativeName to set
     */
    @Override
    public void setSubjectAlternativeName(final String subjectAlternativeName) {
        this.subjectAlternativeName = subjectAlternativeName;
    }

}
