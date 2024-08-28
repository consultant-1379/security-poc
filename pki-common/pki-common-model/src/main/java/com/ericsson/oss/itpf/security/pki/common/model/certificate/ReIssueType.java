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
package com.ericsson.oss.itpf.security.pki.common.model.certificate;

public enum ReIssueType {

    CA("Ca"), CA_WITH_IMMEDIATE_SUB_CAS("Ca_with_immediate_Sub_CAs"), CA_WITH_ALL_CHILD_CAS("Ca_with_all_child_CAs");

    String rekeyType;

    ReIssueType(final String rekeyType) {

        this.rekeyType = rekeyType;
    }

    public String value() {

        return rekeyType;
    }
}
