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
package com.ericsson.oss.itpf.security.pki.manager.common.setupdata;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;

/**
 * This class acts as builder for {@link AuthorityKeyIdentifierSetUpData}
 */
public class AuthorityKeyIdentifierSetUpData {
    /**
     * Method that returns valid AuthorityKeyIdentifier
     * 
     * @return AuthorityKeyIdentifier
     */
    public AuthorityKeyIdentifier getAuthorityKeyIdentifierForEqual() {
        final AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
        authorityKeyIdentifier.setType(AuthorityKeyIdentifierType.SUBJECT_KEY_IDENTIFIER);
        authorityKeyIdentifier.setSubjectkeyIdentifier(new SubjectKeyIdentifier());
        authorityKeyIdentifier.setIssuerSubjectAndSerialNumber(new Certificate());
        authorityKeyIdentifier.setCritical(true);
        return authorityKeyIdentifier;
    }

    /**
     * Method that returns different valid AuthorityKeyIdentifier
     * 
     * @return AuthorityKeyIdentifier
     */
    public AuthorityKeyIdentifier getAuthorityKeyIdentifierForNotEqual() {
        final AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
        authorityKeyIdentifier.setType(AuthorityKeyIdentifierType.ISSUER_DN_SERIAL_NUMBER);
        authorityKeyIdentifier.setSubjectkeyIdentifier(new SubjectKeyIdentifier());
        authorityKeyIdentifier.setCritical(false);
        return authorityKeyIdentifier;
    }

}
