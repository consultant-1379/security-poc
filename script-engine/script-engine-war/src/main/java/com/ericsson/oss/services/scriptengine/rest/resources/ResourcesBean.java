package com.ericsson.oss.services.scriptengine.rest.resources;

import javax.enterprise.context.ApplicationScoped;

import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.sdk.resources.Resources;

/**
 * Bean to wrap ServiceFramework Resources.
 */
@ApplicationScoped
public class ResourcesBean {

    /**
     * Uses ServiceFramework Resources class to retrieve the Resource object.
     *
     * @param fileLocation
     *            of the file on the file system
     * @return the Resource on the file system
     */
    public Resource getFileSystemResource(final String fileLocation) {
        return Resources.getFileSystemResource(fileLocation);
    }
}