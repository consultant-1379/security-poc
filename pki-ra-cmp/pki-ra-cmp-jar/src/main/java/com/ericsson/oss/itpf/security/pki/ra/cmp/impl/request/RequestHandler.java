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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.TransactionIdHandlerException;

/**
 * This is an interface which is used for serving CMP requests. Any new requestHandler to be written in case to support a new requestType, should implement this interface.
 * 
 * @author tcsdemi
 *
 */
public interface RequestHandler {
    /**
     * This method is for handling all CMP requests from node:
     * <p>
     * 1.InitializationRequest<br>
     * 2.PollRequest<br>
     * 3.CertConfReqeust<br>
     * 4.KeyUpdateRequest<br>
     * All CMP requests will be implementing this interface with validators annotation pushing message into DB, dispatching into event bus and transactionID handling.
     * <p>
     * 1.Validator annotations: <br>
     * All RequestHandler Implementations will have explicit validators defined udner two categories <br>
     * a. CommonValidators: which are header/body/Nonce etc<br>
     * b. VC validators : which are CRL/Digital Signature validators
     * <p>
     * 2.Saving data into DB:<br>
     * Only IR and KUR requests needs to be saved in DB, for rest of the messages there is no need for message to be stored
     * <p>
     * 3.Dispatching onto modeled event bus:<br>
     * Only IR and KUR are the initial messages which needs to return a userCertificate. For this purpose, RA request are sent to modeled event bus to PKI-manager which will generate certificate and
     * send it back to RA
     * <p>
     * 4.TransactionID handling: For IP/KUP transactionID can be null and PKI-RA will be generating it based on uniquesness maintained across entityName and TransacionId(if sent) from node. Please
     * refer to TransactionIdHandler for more details.
     * 
     * 
     * @param pKIRequestmessage
     *            This is the requestMessage which needs to be processed/handled as above.
     * @return
     * @throws TransactionIdHandlerException
     *             This exception is thrown in case transaction ID is not present in DB(in case of Poll/CertConf)or in case it is already in use.
     */
    String handle(RequestMessage pKIRequestmessage) throws TransactionIdHandlerException;

}
