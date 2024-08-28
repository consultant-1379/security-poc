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
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.api;

import java.io.Serializable;
import java.util.List;

public interface CredentialManagerTrustStoreOnly extends Serializable {

    
// cope data from com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.TrustStoreOnlyType
//    @XmlElement(required = true)
//    protected String trustprofilename;
//    @XmlElement(required = true)
//    protected List<TrustStoreType> truststore;
//    protected List<CrlStoreType> crlstore;
//    protected CommandType postscript;
//    protected CheckActionListType oncheckresult;
    

	/**
	 * 
	 * @return End Entity Profile Name
	 */
	String getTrustProfileName();

	
	/**
	 * @return the trustStores
	 */
	List<CredentialManagerTrustStore> getTrustStores();
	       
	/**
         * 
         * @return
         */
        List<CredentialManagerTrustStore> getCrlStores();

	/**
	 * @return the trustStores
	 */
	List<CredentialManagerCheckAction> getCheckAction();

	/**
	 * 
	 * @return
	 */
	CredentialManagerPostScriptCaller getPostScript();

}