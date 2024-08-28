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
package com.ericsson.oss.itpf.security.credmsapi.business;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustStoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.TrustHandlerException;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.TrustHandler;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;

public class TrustManager {

    private static final Logger LOG = LogManager.getLogger(TrustManager.class);

    // wrapper to call service REST or remote EJB
    final private CredMServiceWrapper service;

    private CredentialManagerTrustMaps trustMaps = null;

    /**
     * 
     */
    public TrustManager(final CredMServiceWrapper serviceWrapper) {
        this.service = serviceWrapper;
        //System.out.println(" wrapper istantiated is " + this.service);
    }

    /**
     * cleanTruststore
     * 
     * @param tsInfoList
     * @param ksInfoList
     * @throws IssueCertificateException
     */
    public void clearTruststores(final List<TrustStoreInfo> tsInfoList) {

        final TrustHandler trustHandler = new TrustHandler();
        for (final TrustStoreInfo tsInfo : tsInfoList) {
            try {
                trustHandler.clearTruststore(tsInfo);
            } catch (final TrustHandlerException e) {
                // something wrong in the keystore
                //e.printStackTrace();
                System.out.println("clearTruststores: DELETE trustStore");
                LOG.info("clearTruststores: DELETE trustStore");
                tsInfo.delete();
            }
        }
    }

    /**
     * getTrust
     * 
     * @param entityProfileName
     * @param tsInfoList
     * @throws IssueCertificateException
     */
    public void retrieveTrust(final String entityProfileName) throws IssueCertificateException {
        /**
         * get and write Trust
         */
        final TrustHandler trustHandler = new TrustHandler();

        try {
            //System.out.println(" wrapper passed to handler is " + this.service);
            this.trustMaps = trustHandler.getTrustCertificates(entityProfileName, this.service);
        } catch (final TrustHandlerException e) {
            throw new IssueCertificateException("trustHandler exception" + e.getMessage());
        }
    }

    /**
     * writeTrust
     * 
     * @param entityProfileName
     * @param tsInfoList
     * @throws IssueCertificateException
     */
    public void writeTrust(final List<TrustStoreInfo> tsInfoList) throws IssueCertificateException {

        if (this.getTrustMaps() == null) {
            LOG.error(ErrorMsg.API_ERROR_BUSINESS_GET_TRUSTCHAIN);
            throw new IssueCertificateException("writeTrust trust map is null");
        }

        /**
         * get and write Trust
         */
        final TrustHandler trustHandler = new TrustHandler();

        try {
            for (final TrustStoreInfo tsInfo : tsInfoList) {
                trustHandler.writeTrustCertificates(tsInfo, this.getTrustMaps());
            }
        } catch (final TrustHandlerException e) {
            throw new IssueCertificateException("trustHandler exception" + e.getMessage());
        }
    }

    // GETTER AND SETTER

    /**
     * @return the trustMaps
     */
    public CredentialManagerTrustMaps getTrustMaps() {
        return this.trustMaps;
    }

    /**
     * @param trustMaps
     *            the trustMaps to set
     */
    public void setTrustMaps(final CredentialManagerTrustMaps trustMaps) {
        this.trustMaps = trustMaps;
    }

} // end of TrustManager

