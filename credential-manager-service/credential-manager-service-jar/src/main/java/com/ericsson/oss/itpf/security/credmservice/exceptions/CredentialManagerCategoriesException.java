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
package com.ericsson.oss.itpf.security.credmservice.exceptions;

public class CredentialManagerCategoriesException extends Exception{

	/**
    *
    */
   public CredentialManagerCategoriesException() {
       super();
   }

   /**
    * @param message
    * @param cause
    */
   public CredentialManagerCategoriesException(final String message, final Throwable cause) {
       super("credential-manager-service: CredentialManagerCategoriesException: " + message, cause);
   }

   /**
    * @param message
    */
   public CredentialManagerCategoriesException(final String message) {
       super("credential-manager-service: CredentialManagerCategoriesException: " + message);
   }

   /**
    * @param cause
    */
   public CredentialManagerCategoriesException(final Throwable cause) {
       super(cause);
   }
	
}
