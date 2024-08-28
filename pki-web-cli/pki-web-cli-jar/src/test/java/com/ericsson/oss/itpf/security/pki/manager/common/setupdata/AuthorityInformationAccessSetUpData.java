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

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AccessDescription;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityInformationAccess;

/**
 * This class acts as builder for {@link AuthorityInformationAccessSetUpData}
 */
public class AuthorityInformationAccessSetUpData {
    AccessDescriptionSetUpData accessDescriptionSetUpData = new AccessDescriptionSetUpData();

    /**
     * Method that returns valid AuthorityInformationAccess
     * 
     * @return AuthorityInformationAccess
     */
    public AuthorityInformationAccess getAuthorityInformationAccessForEqual() {
        final AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess();
        final List<AccessDescription> accessDescriptionList = new ArrayList<AccessDescription>();
        final AccessDescription accesDescription = accessDescriptionSetUpData.getAccessDescriptionForEqual();
        accessDescriptionList.add(accesDescription);
        authorityInformationAccess.setAccessDescriptions(accessDescriptionList);
        authorityInformationAccess.setCritical(true);
        return authorityInformationAccess;
    }

    /**
     * Method that returns different valid AuthorityInformationAccess
     * 
     * @return AuthorityInformationAccess
     */
    public AuthorityInformationAccess getAuthorityInformationAccessForNotEqual() {
        final AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess();
        final List<AccessDescription> accessDescriptionList = new ArrayList<AccessDescription>();
        final AccessDescription accesDescription = accessDescriptionSetUpData.getAccessDescriptionForNotEqual();
        accessDescriptionList.add(accesDescription);
        authorityInformationAccess.setAccessDescriptions(accessDescriptionList);
        authorityInformationAccess.setCritical(false);
        return authorityInformationAccess;
    }

}
