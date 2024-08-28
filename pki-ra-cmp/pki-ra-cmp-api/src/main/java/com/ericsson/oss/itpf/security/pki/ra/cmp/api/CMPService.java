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
package com.ericsson.oss.itpf.security.pki.ra.cmp.api;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.asynchresponse.RestSynchResponse;

/**
 * This class is a Local(Stateless) EJB which provides CMPService to Entities through Rest service.
 * 
 * @author tcsdemi
 */
@EService
@Local
public interface CMPService {
    /**
     * 
     * <p>
     * CMPService will take input as RequestMessage, high level application flow as below:
     * <p>
     * 1) Validation of the RequestMessage:
     * </p>
     * <p>
     * a. Basic validation of Header and body is done. Header is validated for CMPmessage version 2000, if not exception is thrown and an error response is sent back to entity. Also sender/recipient
     * names are checked if they are in DN format or not, otherwise exception is thrown.
     * </p>
     * <p>
     * b. Body validation is performed based on requestType, wherein only IR,KUR,PollReq and CertConf are only supported. otherwise exception is thrown and error response sent back to entity.
     * </p>
     * <p>
     * c. PKIMessage is validated for its Digital signature.
     * </p>
     * 
     * <p>
     * 2) As per the requestType, there are RequestHandlers which deal with:
     * <p>
     * a.persisting the message in DB.
     * <p>
     * b. dispatching the request onto PKI-Manager queue.
     * <p>
     * c. generating new TransactionID in case not present in the request message
     * </p>
     * <p>
     * 3) As per each Request there will be Response Builders as:
     * <p>
     * a. For IR request an IPWithWaitResponseBuilder will build a waiting response.
     * <p>
     * b. For PollRequest a PollResponseBuilder will build either an IP,KUP or PollResponse based on the response saved in DB. Actual IP is received from PKI-Manager and stored in DB (not handled by
     * EJB Service)
     * <p>
     * c. For CertConf Request PKIConfResponseBuilder will build a confirmation response.
     * <p>
     * 
     * 4) In case there are any failure in EJB Service all internal exceptions are handled by forming a FailureResponse with ErrorMsgContent and send back to entity
     * 
     * </p>
     * 
     * @param requestMessage
     *            This request message is a PKIMessage which can be CMP ir, Kur, PollReq or CertConf message.
     * @return byte[] This is an actual response from ResponseBuilders or a FailureResponse in case of any internal exceptions.
     * @throws ResponseBuilderException
     *             This exception is a wrapper exception for all other exceptions and is thrown in case of any exceptions while building Responses.
     */
    byte[] provide(final RequestMessage requestMessage) throws ResponseBuilderException;

    /**
     * 
     * <p>
     * CMPService will take input as RequestMessage and AsynchronousResponse as inputs, high level application flow as below: This method is invoked when nodes (eg: GEN2) do not support polling
     * request or IP_WITH_WAIT as a response. Node tend to wait until IP is sent back to them or an application Timeout occurs with SERVICE UNAVAILABLE from server side.
     * <p>
     * 1) Validation of the RequestMessage:
     * </p>
     * <p>
     * a. Basic validation of Header and body is done Header is validated for CMPmessage version 2000, if not exception is thrown and an error response is sent back to entity. Also sender/recepient
     * names are checked if they are in DN format or not, otherwise exception is thrown.
     * </p>
     * <p>
     * b. Body validation is performed based on requestType, wherein only IR,KUR and CertConf are only supported. otherwise exception is thrown and error response sent back to entity.
     * </p>
     * <p>
     * c. PKIMessage is validated for its Digital signature.
     * </p>
     * 
     * <p>
     * 2) As per the requestType, there are RequestHandlers which deal with:
     * <p>
     * a.persisting the message in DB.
     * <p>
     * b. dispatching the request onto PKI-Manager queue.
     * <p>
     * c. generating new TransactionID in case not present in the request message
     * </p>
     * <p>
     * 3) As per each Request there will be Response Builders as:
     * <p>
     * a. For IR request an IPResponse will build a proper IP response.
     * <p>
     * b. For CertConf Request PKIConfResponseBuilder will build a confirmation response.
     * <p>
     * 
     * 4) In case there are any failure in EJB Service all internal exceptions are handled by forming a FailureResponse with ErrorMsgContent and send back to entity
     * 
     * </p>
     * 
     * @param requestMessage
     *            This request message is a PKIMessage which can be CMP ir, Kur, PollReq or CertConf message.
     * @param synchResponse
     *            This is an synchronousResponse response object which allows us to send an synchronousResponse response to the rest service.
     * @throws ResponseBuilderException
     *             This is a high level Service exception which will be thrown back to REST. This exception is a subclass of ProtocolException.
     */
    void provide(final RequestMessage requestMessage, final RestSynchResponse synchResponse) throws ResponseBuilderException;

    /**
     * This is used to get the sender name for poll request and certconf messages from the cmpmessages table.
     * 
     * @param requestMessage
     *            This request message is a PKIMessage which can be CMP ir, Kur, PollReq or CertConf message.
     * @return sender name
     *            This is a sender name contains Name of the sender of CMP request message
     */
    String getSenderName(final RequestMessage requestMessage);

}