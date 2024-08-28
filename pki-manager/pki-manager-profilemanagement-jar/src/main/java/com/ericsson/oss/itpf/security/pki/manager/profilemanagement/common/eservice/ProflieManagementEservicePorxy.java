/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.eservice;

import javax.enterprise.context.ApplicationScoped;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.api.CAEntityManagementService;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.api.EntityManagementService;

@ApplicationScoped
public class ProflieManagementEservicePorxy {

    @EServiceRef
    CAEntityManagementService caEntityManagementService;

    public CAEntityManagementService getCaEntityManagementService() {
        return caEntityManagementService;
    }

    @EServiceRef
    EntityManagementService entityManagementService;

    public EntityManagementService getEntityManagementService() {
        return entityManagementService;
    }

}
