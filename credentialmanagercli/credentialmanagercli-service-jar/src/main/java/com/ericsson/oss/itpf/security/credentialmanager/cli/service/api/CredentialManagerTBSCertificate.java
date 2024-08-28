/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.api;

import java.io.Serializable;

public interface CredentialManagerTBSCertificate extends Serializable {

    /**
     * @return the version
     */
    //    BigInteger getVersion();

    /**
     * @return the subjectDN
     */
    String getSubjectDN();

    /**
     * @return the issuerDN
     */
    //    String getIssuerDN();

    /**
     * @return the certificateExtension
     */
    CredentialManagerCertificateExt getCertificateExtension();

    /**
     * @return
     */
    String getEntityName();

}