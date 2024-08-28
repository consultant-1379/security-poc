/*
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 */
package com.ericsson.oss.services.scriptengine.api;

import com.ericsson.oss.itpf.sdk.core.classic.ServiceFinderBean;

/**
 * Class ServiceFinderBeanProvider used for providing the ServiceFinderBean from Service Framework.
 * This class is used to make testing possible against this and therefore is NOT FOR EXTERNAL USE.
 */
public class ServiceFinderBeanProvider {

    private ServiceFinderBean serviceFinderBean;

    public ServiceFinderBean getServiceFinderBean() {
        if (serviceFinderBean == null) {
            serviceFinderBean = new ServiceFinderBean();
        }
        return serviceFinderBean;
    }

}
