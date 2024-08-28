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
package com.ericsson.oss.itpf.security.pki.manager.common.enums;

/**
 * This enum type is for UnPublish CRL types
 * 
 * @author xjagcho
 *
 */
public enum CRLUnpublishType {
    REVOKED_CA_CERTIFICATE, EXPIRED_CA_CERTIFICATE, USER_INVOKED_REQUEST, CRL_EXPIRED;
}
