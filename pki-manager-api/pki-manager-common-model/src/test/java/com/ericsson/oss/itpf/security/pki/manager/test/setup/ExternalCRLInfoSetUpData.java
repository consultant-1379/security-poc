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
package com.ericsson.oss.itpf.security.pki.manager.test.setup;

import java.text.ParseException;
import java.text.SimpleDateFormat;

import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;

/**
 * This class acts as builder for {@link ExternalCRLInfoSetUpData}
 */
public class ExternalCRLInfoSetUpData {

    private static final String EQUAL_ISSUED_TIME = "10-20-2020";
    private static final String NOT_EQUAL_ISSUED_TIME = "10-10-2030";

    /**
     * Method that returns valid ExternalCRLInfo object
     * 
     * @return ExternalCRLInfo
     * @throws ParseException
     */
    public ExternalCRLInfo getExternalCRLInofForCreate() throws ParseException {
        final ExternalCRLInfo externalCRLInfo = new ExternalCRLInfo();
        externalCRLInfo.setAutoUpdate(true);
        externalCRLInfo.setAutoUpdateCheckTimer(30);
        externalCRLInfo.setNextUpdate((new SimpleDateFormat(CommonConstants.DATE_FORMAT)).parse(EQUAL_ISSUED_TIME));
        externalCRLInfo.setUpdateURL("URL");
        return externalCRLInfo;
    }

    /**
     * Method that returns different valid ExternalCRLInfo object
     * 
     * @return ExternalCRLInfo
     * @throws ParseException
     */
    public ExternalCRLInfo getExternalCRLInfoForCreateNotEqual() throws ParseException {
        final ExternalCRLInfo externalCRLInfo = new ExternalCRLInfo();
        externalCRLInfo.setAutoUpdate(false);
        externalCRLInfo.setAutoUpdateCheckTimer(30);
        externalCRLInfo.setNextUpdate((new SimpleDateFormat(CommonConstants.DATE_FORMAT)).parse(NOT_EQUAL_ISSUED_TIME));
        externalCRLInfo.setUpdateURL("URL");
        return externalCRLInfo;
    }
}
