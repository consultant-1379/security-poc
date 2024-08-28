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
package com.ericsson.oss.itpf.security.pki.manager.model.certificate;

/**
 * This class is used to map the types of reissue of the certificate
 * 
 * @author tcschdy
 *
 */
public enum CAReIssueType {

    RENEW_SUB_CAS("Renew_Sub_CAs"),

    RENEW_SUB_CAS_WITH_REVOCATION("Renew_Sub_CAs_with_revocation"),

    REKEY_SUB_CAS("Rekey_Sub_CAs"),

    REKEY_SUB_CAS_WITH_REVOCATION("Rekey_Sub_CAs_with_revocation"),

    NONE("None");

    String reIssueType;

    CAReIssueType(final String reIssueType) {

        this.reIssueType = reIssueType;

    }

    public String value() {

        return reIssueType;

    }

}
