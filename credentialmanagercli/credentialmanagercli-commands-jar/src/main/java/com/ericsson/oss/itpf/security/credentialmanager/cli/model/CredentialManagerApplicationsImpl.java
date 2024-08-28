/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credentialmanager.cli.model;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.ApplicationType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.ApplicationsType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerApplication;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerApplications;

public class CredentialManagerApplicationsImpl implements CredentialManagerApplications {
    /**
     * 
     */
    private static final long serialVersionUID = -1339739185679099076L;
    private final List<CredentialManagerApplication> applications = new ArrayList<CredentialManagerApplication>();

    public CredentialManagerApplicationsImpl(final Object applicationsObj) {
        ApplicationsType applicationsType;

        if (applicationsObj != null && applicationsObj instanceof ApplicationsType) {
            applicationsType = (ApplicationsType) applicationsObj;
        } else {
            throw new CredentialManagerException("Loading information of XML Applications Type...[Failed]");
        }
        for (final ApplicationType application : applicationsType.getApplication()) {
            applications.add(new CredentialManagerApplicationImpl(application));
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * com.ericsson.oss.itpf.security.credentialmanager.cli.service.model.
     * CredentialManagerApplications
     * #getApplications()
     */
    @Override
    public List<CredentialManagerApplication> getApplications() {
        return applications;
    }
}
