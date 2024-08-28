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

public class CredentialManagerProfileInfo implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * ProfileInfo represents a collection of informations related to the Profiles needed in the request chain for obtaining a certificate
     */

    private String issuerName;
    private CredentialManagerSubject subjectByProfile;
    private CredentialManagerSubjectAltName subjectDefaultAlternativeName;

    /**
     * TO VERIFY if is necessary to retrieve otp from PKI or it is possible to generate a new one using KeyManagment api private String otPassword;
     */
    /**
     * TO VERIFY if PKI will include this field in the Certificate Profile - otherwise XML
     */
    private CredentialManagerAlgorithm keyPairAlgorithm;
    /**
     * TO VERIFY if it will used the information in XML private DERSet extentionAttributes;
     */
    private CredentialManagerCertificateExtensions extentionAttributes;
    private CredentialManagerAlgorithm signatureAlgorithm;

    /**
     * @return the issuerName
     */
    public String getIssuerName() {
        return issuerName;
    }

    /**
     * @param issuerName
     *            the issuerName to set
     */
    public void setIssuerName(final String issuerName) {
        this.issuerName = issuerName;
    }

    /**
     * @return the subjectAlternativeName
     */
    public CredentialManagerSubjectAltName getSubjectDefaultAlternativeName() {
        return subjectDefaultAlternativeName;
    }

    /**
     * DERSet
     * 
     * @param subjectAlternativeName
     *            the subjectAlternativeName to set
     */
    public void setSubjectDefaultAlternativeName(final CredentialManagerSubjectAltName subjectDefaultAlternativeName) {
        this.subjectDefaultAlternativeName = subjectDefaultAlternativeName;
    }

    /**
     * @return the keyPairAlgorithm
     */
    public CredentialManagerAlgorithm getKeyPairAlgorithm() {
        return keyPairAlgorithm;
    }

    /**
     * @param algorithm
     *            the keyPairAlgorithm to set
     */
    public void setKeyPairAlgorithm(final CredentialManagerAlgorithm algorithm) {
        this.keyPairAlgorithm = algorithm;
    }

    /**
     * @return the extentionAttributes
     */
    public CredentialManagerCertificateExtensions getExtentionAttributes() {
        return extentionAttributes;
    }

    /**
     * @param extentionAttributes
     *            the extentionAttributes to set
     */
    public void setExtentionAttributes(final CredentialManagerCertificateExtensions extentionAttributes) {
        this.extentionAttributes = extentionAttributes;
    }

    /**
     * @return the signatureAlgorithm
     */
    public CredentialManagerAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * @param signatureAlgorithm
     *            the signatureAlgorithm to set
     */
    public void setSignatureAlgorithm(final CredentialManagerAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * @return the subjectByProfile
     */
    public CredentialManagerSubject getSubjectByProfile() {
        return subjectByProfile;
    }

    /**
     * @param subjectByProfile
     *            the subjectByProfile to set
     */
    public void setSubjectByProfile(final CredentialManagerSubject subjectByProfile) {
        this.subjectByProfile = subjectByProfile;
    }

}
