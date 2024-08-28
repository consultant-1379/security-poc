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

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectKeyIdentifier;

/**
 * This class acts as builder for {@link SubjectKeyIdentifierSetUpData}
 */
public class SubjectKeyIdentifierSetUpData {

    /**
     * Method that returns valid SubjectKeyIdentifier object
     * 
     * @return SubjectKeyIdentifier
     */
    public SubjectKeyIdentifier getSubjectKeyIdentifierForEqual() {
        final SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier();
        subjectKeyIdentifier.setCritical(true);
        subjectKeyIdentifier.setKeyIdentifier(new KeyIdentifier());

        return subjectKeyIdentifier;
    }

    /**
     * Method that returns different valid SubjectKeyIdentifier object
     * 
     * @return SubjectKeyIdentifier
     */
    public SubjectKeyIdentifier getSubjectKeyIdentifierForNotEqual() {
        final SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier();
        subjectKeyIdentifier.setCritical(false);
        subjectKeyIdentifier.setKeyIdentifier(new KeyIdentifier());

        return subjectKeyIdentifier;
    }

}
