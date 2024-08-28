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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateFormat;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustFormat;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.StorageConstants;

public final class StorageFormatUtils {

	private static final Logger LOG = LogManager.getLogger(StorageFormatUtils.class);
	
    /*
     * Convert TrustFormat enum to array of StorageConstant strings: PKCS12, JKS, JCEKS, BASE_64
     */
    private static String[] TrustFormatTable = { StorageConstants.PKCS12_STORE_TYPE, StorageConstants.JKS_STORE_TYPE, 
        StorageConstants.JCEKS_STORE_TYPE, StorageConstants.BASE64_PEM_STORE_TYPE, StorageConstants.LEGACY_XML_STORE_TYPE };
    /*
     * Convert CertificateFormat enum to array of StorageConstant strings: PKCS12, JKS, JCEKS, BASE_64
     */
    private static String[] CertFormatTable = { StorageConstants.PKCS12_STORE_TYPE, StorageConstants.JKS_STORE_TYPE, 
        StorageConstants.JCEKS_STORE_TYPE, StorageConstants.BASE64_PEM_STORE_TYPE, StorageConstants.LEGACY_XML_STORE_TYPE };

    /**
     * @return the TrustFormatTable item
     */
    public static String getTrustFormatString(final TrustFormat trustFormat) {
        return TrustFormatTable[trustFormat.ordinal()];
    }
    

    /**
     * @return the CertFormatTable item
     */
    public static String getCertFormatString(final CertificateFormat certFormat) {
        return CertFormatTable[certFormat.ordinal()];
    }

    /**
     * @return the CertFormatTable item
     */
    public static TrustFormat convertCertToTrustFormat(final CertificateFormat certFormat) {

        try {
            switch (certFormat) {
            case BASE_64:
                return TrustFormat.BASE_64;
            case JCEKS:
                return TrustFormat.JCEKS;
            case JKS:
                return TrustFormat.JKS;
            case PKCS12:
                return TrustFormat.PKCS12;
            case LEGACY_XML:
                return TrustFormat.LEGACY_XML;
            default:
                return TrustFormat.JKS;
            }
        } catch (final Exception e) {
        	LOG.error(ErrorMsg.API_ERROR_BUSINESS_UTILS_CONVERT_TRUSTFORMAT,certFormat);
            return null;
        }
    }
    
    /**
     * 
     * @param String type
     * @return boolean
     */
    public static Boolean isValidStorageConstant(final String type) {

        try {
            switch (type) {
            case StorageConstants.BASE64_PEM_STORE_TYPE:
            case StorageConstants.JCEKS_STORE_TYPE:
            case StorageConstants.JKS_STORE_TYPE:
            case StorageConstants.PKCS12_STORE_TYPE:
                return true;
            default:
                return false;
            }
        } catch (final Exception e) {
            LOG.error(ErrorMsg.API_ERROR_BUSINESS_UTILS_CHECK_STORAGETYPE,type);
            return false;
        }
    }
}
