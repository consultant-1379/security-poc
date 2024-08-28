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

import javax.xml.bind.annotation.XmlElement;

public class CredentialManagerSubjectKeyIdentifier extends CredentialManagerCertificateExtension implements Serializable {

    /**
	 * 
	 */
    private static final long serialVersionUID = -5957736622585327343L;
    @XmlElement(required = true)
    protected String keyIdentifierAlgorithm;

    /**
     * @return the key identifier algorithm
     */
    public String getKeyIdentifierAlgorithm() {
        return keyIdentifierAlgorithm;
    }

    /**
     * @param enabled
     *            the enabled to set
     */
    public void setKeyIdentifierAlgorithm(final String keyIdentifierAlgorithm) {
        this.keyIdentifierAlgorithm = keyIdentifierAlgorithm;
    }

    @Override
    public String toString() {
        return " Key Identifier Algorithm : " + keyIdentifierAlgorithm;
    }

}
