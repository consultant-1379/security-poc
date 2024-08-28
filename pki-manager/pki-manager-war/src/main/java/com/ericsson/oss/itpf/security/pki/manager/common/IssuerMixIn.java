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
package com.ericsson.oss.itpf.security.pki.manager.common;

import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.rest.serializers.IssuerSerializer;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

/**
 * Mix-in abstract class that is kind of a proxy to the {@link CertificateProfile} class.
 * 
 * Overriding json annotation for issuer attribute
 */

public abstract class IssuerMixIn {

    @JsonSerialize(using = IssuerSerializer.class)
    abstract CAEntity getIssuer();
}
