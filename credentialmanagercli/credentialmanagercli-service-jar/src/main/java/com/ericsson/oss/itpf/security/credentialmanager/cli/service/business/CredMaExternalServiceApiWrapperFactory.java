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
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.business;

import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaExternalServiceApiWrapper;

public class CredMaExternalServiceApiWrapperFactory {
    

    private CredMaExternalServiceApiWrapper extServiceApi;

    public CredMaExternalServiceApiWrapper getInstance(final String environment) {
            
            switch (environment) {
            
                    case "CREDMAN_SERVICE_API":
                            this.extServiceApi = new CredMaExternalServiceApiWrapperImpl();
                            break;

                    case "MOCKED_API":
                            this.extServiceApi = new CredMaServiceApiWrapperMock();
                            break;
                            
                    default:
                            throw new UnsupportedOperationException(
                                    "Not supported environment: " + environment);
            }
            return this.extServiceApi;
    }

}
