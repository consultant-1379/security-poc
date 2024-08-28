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
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.api;

import java.util.List;

import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.Actions;

public interface CredMaServiceApiController {

    /**
     * 
     * @param appInfo
     * @param forceOverWrite
     * @return
     */
    int generateKeyAndTrustStore(ApplicationCertificateConfigInformation appInfo, boolean forceOverWrite);

    /**
     * @param credMKeyStore
     * @param serviceApi
     * @return
     */
    //    boolean isCertificateValid(CredentialManagerKeyStore credMKeyStore, String xmlSubject);

    /**
     * @param noLoop
     * @param myCert
     * @param forceOverwrite
     * @param isCheck
     * @param firstDayRun
     * @return
     */
    int generateMyOwnCertificate(CredentialManagerCertificate myCert, boolean forceOverWrite, boolean noLoop, boolean isCheck, boolean firstDayRun);

    /**
     * @param appInfo
     * @param firstDailyRun
     * @return
     */
    List<Actions> checkActionToPerform(ApplicationCertificateConfigInformation appInfo, boolean firstDailyRun);

}
