/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.local.service.ejb;

import javax.ejb.*;

import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.sdk.resources.Resources;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.SdkResourceManagementLocalService;

/**
 * Implementation for SdkResourceManagementLocalService which handles all the Resource SDK operations
 * 
 * @author tcsnapa
 * 
 */
@Stateless
public class SdkResourceManagementLocalServiceBean implements SdkResourceManagementLocalService {

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public int write(final String absoluteFileURI, final byte[] content, final boolean append) {

        final Resource resource = getFileSystemResource(absoluteFileURI);
        if (resource != null) {
            try {
                if (resource.supportsWriteOperations()) {
                    return resource.write(content, append);
                }
            } finally {
                close(resource, absoluteFileURI);
            }
        }

        return 0;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public byte[] getBytes(final String absoluteFileURI) {
        final Resource resource = getFileSystemResource(absoluteFileURI);
        if (resource != null) {
            try {
                return resource.getBytes();
            } finally {
                close(resource, absoluteFileURI);
            }
        }
        return null;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public boolean delete(final String absoluteFileURI) {

        final Resource resource = getFileSystemResource(absoluteFileURI);
        if (resource != null) {

            return resource.delete();
        }
        return false;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public String getResource(final String absoluteFileURI) {

        final Resource resource = getFileSystemResource(absoluteFileURI);
        if (resource != null) {
            try {
                return resource.getName();
            } finally {
                close(resource, absoluteFileURI);
            }
        }
        return null;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public boolean isResourceExist(final String absoluteFileURI) {
        final Resource resource = getFileSystemResource(absoluteFileURI);
        if (resource != null) {
            try {
                return resource.exists();
            } finally {
                close(resource, absoluteFileURI);
            }
        }
        return false;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public byte[] getBytesAndDelete(final String absoluteFileURI) {
        final Resource resource = getFileSystemResource(absoluteFileURI);
        if (resource != null) {
            try {
                return resource.getBytes();
            } finally {
                resource.delete();
            }
        }
        return null;
    }

    private Resource getFileSystemResource(final String absoluteFileURI) {
        final Resource resource = Resources.getFileSystemResource(absoluteFileURI);
        return resource;
    }

    private void close(final Resource resource, final String absoluteFileURI) {
        Resources.safeClose(resource.getClass().getResourceAsStream(absoluteFileURI));
    }
}