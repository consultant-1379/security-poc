/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.impl;

import java.io.File;

import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerCategoriesException;
import com.ericsson.oss.itpf.security.credmservice.util.AppCategoryXmlConfiguration;
import com.ericsson.oss.itpf.security.credmservice.util.PropertiesReader;

/**
 * DU: Solution for PKI External CA
 *
 */
public class CategoryManagement {


    private CategoryManagement() {
    } // Only static methods

    public static String getServiceName() throws CredentialManagerInvalidEntityException {
        final File xmlRootPath = new File(PropertiesReader.getConfigProperties().getProperty("path.xml.pki.configuration"));
        final File xmlCategoryPath = new File(xmlRootPath.getParent() + "/PKICategories.xml");
        AppCategoryXmlConfiguration categoryObj = null;
        try {
            categoryObj = new AppCategoryXmlConfiguration(xmlCategoryPath);
        } catch (final CredentialManagerCategoriesException e) {
            throw new CredentialManagerInvalidEntityException("Error parsing xml category file in path: " + xmlCategoryPath.toString());
        }
        return categoryObj.getServiceCategory();
    }
}
