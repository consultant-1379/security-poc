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
package com.ericsson.oss.itpf.security.pki.ra.cmp.persistence;

/**
 * Persistent Units will be different one will be JTA_Managed(PERSIST_UNIT) and
 * one will be RESOURCE_LOCAL(UPDATE_UNIT).<br>
 *
 * @author tcsdemi
 *
 */
public class PersistenceUnit {
    private PersistenceUnit() {
    }

    public static final String PERSIST_UNIT = "pkiradb";
}
