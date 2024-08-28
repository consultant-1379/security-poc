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
package com.ericsson.oss.itpf.security.credmservice.api;

import java.util.List;

import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;

public interface ExtCACRLManagementInterface {

    /**
     * @param caName
     * @return
     */
    List<ExternalCRLInfo> listExternalCRLInfo(String caName);

}
