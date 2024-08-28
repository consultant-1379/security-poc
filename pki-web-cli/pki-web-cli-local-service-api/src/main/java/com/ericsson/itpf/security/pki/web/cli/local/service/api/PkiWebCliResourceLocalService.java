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
package com.ericsson.itpf.security.pki.web.cli.local.service.api;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;

/**
 * This interface is for providing centralized management of File operations in pki-web-cli using SDK Resource API .
 * 
 * @author xsrirko
 * 
 */
@EService
@Local
public interface PkiWebCliResourceLocalService {

    /**
     * Write to the file in path specified by absoluteFileURI
     *
     * @param absoluteFileURI
     *            Path where the file is located.An absolute URI to file resource.
     * @param content
     *            Content to be written
     * @param append
     *            whether content should be appended or it should overwrite existing content.
     * @return int number of bytes written
     */
    int write(final String absoluteFileURI, final byte[] content, final boolean append);

    /**
     * Returns resource content as byte array. Returns null if file resource can not be found.
     *
     * @param absoluteFileURI
     *            Path where the file is located.An absolute URI to file resource.
     * @return byte[] of the file.
     */
    byte[] getBytes(final String absoluteFileURI);

    /**
     * Delete resource.
     *
     * @param absoluteFileURI
     *            Path where the file is located.An absolute URI to file resource.
     * @return true in case resource was successfully deleted or false otherwise.
     */
    boolean delete(final String absoluteFileURI);

    /**
     * Returns resource content as byte array and deletes the File from Path. Returns null if file resource can not be found.
     *
     * @param absoluteFileURI
     *            Path where the file is located.An absolute URI to file resource.
     * @return byte[] of the file.
     */
    byte[] getBytesAndDelete(final String absoluteFileURI);

    /**
     * Returns name of Resource pointing to file system resource identified by provided URI parameter. Returns null if file resource can not be found or is not available for reading.
     *
     * @param absoluteFileURI
     *            Path where the file is located.An absolute URI to file resource.
     * @return fileName
     */
    String getResourceName(final String absoluteFileURI);

    /**
     * Returns true if the Resource pointing to file system resource identified by provided URI parameter is exists. Returns false if not exist.
     *
     * @param absoluteFileURI
     *            Path where the file is located.An absolute URI to file resource.
     * @return boolean
     */
    boolean isResourceExist(final String absoluteFileURI);
}
