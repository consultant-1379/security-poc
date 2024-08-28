/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.credmservice.api;

import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;

public interface PKIEntityFactory {

    Entity buildForRequest() throws CredentialManagerInvalidEntityException;

    PKIEntityFactory setId(long id);

    PKIEntityFactory setName(String name);

    Entity buildForCreate() throws CredentialManagerInvalidEntityException;

    PKIEntityFactory setSubject(CredentialManagerSubject subject);

    PKIEntityFactory setSubjectAltName(CredentialManagerSubjectAltName subjectAltName);

    PKIEntityFactory setKeyGenerationAlgorithm(CredentialManagerAlgorithm keyGenerationAlgorithm);

    PKIEntityFactory setEntityProfileName(String entityProfileName);

    Entity buildForUpdate() throws CredentialManagerInvalidEntityException;

    PKIEntityFactory setEntity(Entity pkiEntity);

}
