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
package com.ericsson.oss.itpf.security.credmsapi;

import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;

public class CredMServiceWrapperFactory {

        
    /**
     * 
     * @param mode
     * @param noLoop
     * @return
     * @throws IssueCertificateException 
     */
     public CredMServiceWrapper buildServiceWrapper(final CredMServiceWrapper.channelMode mode, final boolean noLoop) throws IssueCertificateException  {

        // make this way to avoid final declaration (mockito doesn't support final objects)
        CredMServiceWrapper serviceWrapper = null;
        serviceWrapper = new CredMServiceWrapper(mode, noLoop);
                                                
        return serviceWrapper;
    }
     
}
