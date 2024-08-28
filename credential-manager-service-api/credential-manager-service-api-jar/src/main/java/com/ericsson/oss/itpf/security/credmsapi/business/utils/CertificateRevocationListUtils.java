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

import java.security.cert.X509CRL;
import java.util.Date;

import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCRLIdentifier;


public class CertificateRevocationListUtils {

	
	/**
    * buildIdentifier
    * 
    * @param certificate
    * @return
    */
   public static  CredentialManagerCRLIdentifier  buildIdentifier(final X509CRL crl) {
       if (crl != null) {
           return new CredentialManagerCRLIdentifier(crl);
       }
       return null;
   }
   
   /**
    * checkDateValidity
    * 
    * performs a checkValidity on the crl  nextUpdate field
    * @param crl
    */
   /*public static boolean  checkDateValidity(final X509CRL crl)  {
       
       if (crl.getNextUpdate().before(new Date()))   {
    	   
    		   return false;
       }
       else
       {
    	   return true; 
       }
       

 
   }
       */
}
