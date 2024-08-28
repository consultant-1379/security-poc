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
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.CrlHandler;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCrlMaps;

public class CrlManager {

	private static final Logger LOG = LogManager.getLogger(CrlManager.class);

	private CredentialManagerCrlMaps caCrlMaps = null;

	// wrapper to call service REST or remote EJB
	final private CredMServiceWrapper service;
	/**
	 * 
	 */
	public CrlManager(final CredMServiceWrapper serviceWrapper) {
		this.service = serviceWrapper;
		//System.out.println(" wrapper istantiated is " + this.service);
	}

	/**
	 * @return the caCrlList
	 */
	public CredentialManagerCrlMaps getCaCrlMaps() {
		return this.caCrlMaps;
	}

	/**
	 * @param caCrlList
	 *            the caCrlList to set
	 */
	public void setCaCrlMaps(final CredentialManagerCrlMaps caCrlMaps) {
		this.caCrlMaps = caCrlMaps;
	}
	/**
	 * clearCrlStore
	 * 
	 * @param crlstoreInfoList
	 * @param tsInfoList
	 * @throws IssueCertificateException
	 */
	public void clearCrlStore(final List<TrustStoreInfo> crlstoreInfoList) {

		final CrlHandler crlHandler = new CrlHandler();

		for (final TrustStoreInfo crlInfo : crlstoreInfoList) {
			try {
				crlHandler.clearCrlStore(crlInfo);
			} catch (final TrustHandlerException e) {
				// something wrong in the keystore
				System.out.println("clearCrlStore: DELETE keystore");
				LOG.info("clearCrlStore: DELETE keystore");
				crlInfo.delete();
			}
		}
	}

	/**
	 * getCrlList
	 * 
	 * @param entityProfileName
	 * @throws IssueCertificateException
	 */
	public void retrieveCrlList(final String entityProfileName) throws IssueCertificateException {
		/**
		 * get and write Trust
		 */
		final CrlHandler crlHandler = new CrlHandler();

		try {
			//System.out.println(" wrapper passed to handler is " + this.service);
			this.caCrlMaps = crlHandler.getTrustCRLs(this.service, entityProfileName);
		} catch (final TrustHandlerException e) {
			throw new IssueCertificateException("crlHandler exception" + e.getMessage());
		}
	}

	public void writeCrlList(final List<TrustStoreInfo> tsInfoList) throws IssueCertificateException {
		/**
		 * get and write Trust
		 */
		final CrlHandler crlHandler = new CrlHandler();

		if (this.getCaCrlMaps() == null) {
			LOG.error(ErrorMsg.API_ERROR_BUSINESS_CHECK_CRLLIST);
			throw new IssueCertificateException("writeCrlList crl map is null");
		}

		try {
			for (final TrustStoreInfo tsInfo : tsInfoList) {
				crlHandler.writeTrustCRLs(tsInfo, this.caCrlMaps);
			}
		} catch (final TrustHandlerException e) {
			throw new IssueCertificateException("trustHandler exception" + e.getMessage());
		}
	}

}
