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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception;

/**
 * This exception is thrown in case there are any discrepancies on transactionID
 * which is sent by node or which is stored in DB. <br>
 * for eg. In case transaction sent by node is already present in DB for that
 * particular node then TransactionIdHandlerException with error message as
 * "TRANSACTION ID IS IN USE" can be thrown.
 * 
 * @author tcsdemi
 *
 */
public class TransactionIdHandlerException extends RuntimeException {

    private static final long serialVersionUID = -8540377387017257531L;

    /**
     * This exception is thrown in case there are any discrepancies on
     * transactionID which is sent by node or which is stored in DB. <br>
     * for eg. In case transaction sent by node is already present in DB for
     * that particular node then TransactionIdHandlerException with error
     * message as "TRANSACTION ID IS IN USE" can be thrown.
     * 
     * @param errorMessage
     *            This is user defined error message
     */
    public TransactionIdHandlerException(final String errorMessage) {
        super(errorMessage);
    }


}
