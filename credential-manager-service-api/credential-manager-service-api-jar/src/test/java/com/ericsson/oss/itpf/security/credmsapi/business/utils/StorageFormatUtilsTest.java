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
package com.ericsson.oss.itpf.security.credmsapi.business.utils;

import static org.junit.Assert.*;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateFormat;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustFormat;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.StorageConstants;

public class StorageFormatUtilsTest {

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmsapi.business.utils.StorageFormatUtils#convertCertToTrustFormat(com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateFormat)}
     * .
     */
    @Test
    public void testConvertCertToTrustFormat() {
        
        StorageFormatUtils util = new StorageFormatUtils(); //just for cover
        assertTrue(util != null);

        assertTrue(TrustFormat.BASE_64 == StorageFormatUtils.convertCertToTrustFormat(CertificateFormat.BASE_64));

        assertTrue(TrustFormat.JCEKS == StorageFormatUtils.convertCertToTrustFormat(CertificateFormat.JCEKS));

        assertTrue(TrustFormat.JKS == StorageFormatUtils.convertCertToTrustFormat(CertificateFormat.JKS));

        assertTrue(TrustFormat.PKCS12 == StorageFormatUtils.convertCertToTrustFormat(CertificateFormat.PKCS12));

        assertTrue(TrustFormat.JCEKS != StorageFormatUtils.convertCertToTrustFormat(CertificateFormat.PKCS12));

        assertTrue(StorageFormatUtils.convertCertToTrustFormat(null) == null);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmsapi.business.utils.StorageFormatUtils#isValidStorageConstant(String)}
     * .
     */
    @Test
    public void testIsValidStorageConstant() {

        assertTrue(StorageFormatUtils.isValidStorageConstant(StorageConstants.BASE64_PEM_STORE_TYPE));
        assertTrue(StorageFormatUtils.isValidStorageConstant(StorageConstants.JCEKS_STORE_TYPE));
        assertTrue(StorageFormatUtils.isValidStorageConstant(StorageConstants.JKS_STORE_TYPE));
        assertTrue(StorageFormatUtils.isValidStorageConstant(StorageConstants.PKCS12_STORE_TYPE));
        assertFalse(StorageFormatUtils.isValidStorageConstant(StorageConstants.LEGACY_XML_STORE_TYPE));
        assertFalse(StorageFormatUtils.isValidStorageConstant("fakeStoreType"));
        assertFalse(StorageFormatUtils.isValidStorageConstant(""));
        assertFalse(StorageFormatUtils.isValidStorageConstant(null));
    }
}
