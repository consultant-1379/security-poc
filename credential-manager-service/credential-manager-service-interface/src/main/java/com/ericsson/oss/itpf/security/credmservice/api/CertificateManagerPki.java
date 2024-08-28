/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2021
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.api;

import javax.ejb.Local;

import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateAuthority;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustCA;

@Local
public interface CertificateManagerPki {

    /**
     * @param caName
     *            The name of the CA
     * @param isExternal
     *            true if the required trust is for an external CA
     * @return the CredentialManagerCertificateAuthority object related to the CA
     * @throws CredentialManagerInvalidArgumentException
     *             an argument is invalid
     * @throws CredentialManagerProfileNotFoundException
     *             the Trust profile does not exist
     * @throws CredentialManagerCertificateEncodingException
     *             certificate encoding error
     * @throws CredentialManagerInvalidProfileException
     *             the trust profile is invalid
     * @throws CredentialManagerInternalServiceException
     *             internal error
     */
    CredentialManagerCertificateAuthority getTrustCertificates(CredentialManagerTrustCA caName, boolean isExternal);

}
