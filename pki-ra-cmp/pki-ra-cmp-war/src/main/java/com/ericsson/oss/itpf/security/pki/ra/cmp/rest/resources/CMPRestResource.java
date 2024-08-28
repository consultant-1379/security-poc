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

package com.ericsson.oss.itpf.security.pki.ra.cmp.rest.resources;

import java.io.IOException;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.Response;

import org.jboss.resteasy.annotations.Suspend;
import org.jboss.resteasy.spi.AsynchronousResponse;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.PKIMessageStringUtility;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateParseException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidCertificateVersionException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.CMPService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.asynchresponse.RestSynchResponse;

/**
 * <p>
 * This is a REST Resource for CMP Service. Rest calls will be served by POST method processPKIMessage(final byte[] inputByteArray), which will call a local EJBService cMPMessageService for providing
 * CMP Service . PKIResponseToRestResponseMapper maps the response from CMPService to HTTP ErrorCodes/Status.OK response and send it back to the entity as Javax.ws.rs.core.Response
 * <p>
 * 
 * @author tcsdemi
 *
 */
@Path("/")
@Consumes("application/pkixcmp")
@Produces("application/pkixcmp")
public class CMPRestResource {

    @EServiceRef
    CMPService cMPMessageService;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    PKIResponseToRestResponseMapper pKIResponseToRestResponseMapper;

    /**
     * <P>
     * This method which will be invoked once REST URL is hit by the entity for CMP Request. There are two levels of exception handling, one is at EJB layer and other is at REST layer, all user defined
     * application exceptions like <code> validationException and TransactionIdException </code> are being handled at EJB level and an errorMessage is being formed. However in the POST method,
     * inputByteArray needs to be converted into a user-defined object <code>RequestMessage</code>. While parsing this byteArray, if there are any exceptions like
     * <code>CertificateParseException</code> etc these are directly thrown at REST and an HTTP ErrorCode is mapped.
     * 
     * @param inputByteArray
     *            This is PKIMessage which is received as a byteArray in HTTP Request.
     * @return restResponse This is the actual response which will be sent back to Node.Please refer to PKIResponseToRestResponseMapper for http response being sent back to entity.
     * @throws CertificateParseException
     *             This exception occurs when Certificate inside PKIMessage can not be parsed properly. Occurs when inputByteArray is converted to RequestMessage object
     * @throws InvalidCertificateVersionException
     *             This exception occurs when certificate in RequestMessage is not of X509V3 version.
     * @throws IOException
     *             This exception occurs when inputByteArray is being converted to ASN1InputStream and in case the bytes could not be parsed properly.
     * @throws MessageParsingException
     *             This exception occurs on parsing inputByteArray
     * @throws ResponseBuilderException
     *             All exceptions from <code>cMPMessageService.provide(pKIRequestMessage)</code> are being handled at EJB level, on handling these exceptions, an errorMessage is built. While building
     *             this errorMessage, ResponseBuilderException is thrown.
     */
    @POST
    public Response processPkiMessage(final byte[] inputByteArray) throws CertificateParseException, InvalidCertificateVersionException, IOException, MessageParsingException, ResponseBuilderException {
        return processPkiRequestMessage(inputByteArray, null);
    }

    /**
     * <P>
     * This method which will be invoked once REST URL is hit by the entity for CMP Request. This is an "/synch" url, which is used by nodes which do not support Polling request. In this case, CMP
     * application will be sending directly IP response with USer certificate with no waiting status as an intermediate step. Asynchronous response is being used so that when response from PKI-Manager
     * is observed at RA side, this "Asynchronous response" object is set. This will not keep the EJB's engaged, once dispatched onto the queue, EJB will return back to the pool. Only REST service
     * will be kept engaged. There are two levels of exception handling, one at EJB layer and one at REST layer, all user defined application exception like
     * <code> validationException,TransactionIdException </code> are being handled at EJB level and an errorMessage is being formed. However in the POST method, inputByteArray needs to be converted
     * into a user-defined object <code>RequestMessage</code>. While parsing this byteArray, if there are any exceptions like <code>CertificateParseException</code> etc these are directly thrown at
     * REST and an HTTP ErrorCode is mapped.
     * 
     * 
     * @param issuerName
     *            Certificate Authority Name of the Node
     * @param inputByteArray
     *            This is PKIMessage which is sent as a byteArray in HTTP Request.
     * @param response
     *            This is the Asynchronous response(org.jboss.resteasy.spi.AsynchronousResponse)
     * @throws CertificateParseException
     *             This exception occurs when Certificate inside PKIMessage can not be parsed properly. Occurs when inputByteArray is converted to RequestMessage object
     * @throws InvalidCertificateVersionException
     *             This exception occurs when certificate in RequestMessage is not of X509V3 version.
     * @throws IOException
     *             This exception occurs when inputByteArray is being converted to ASN1InputStream and in case the bytes could not be parsed properly.
     * @throws MessageParsingException
     *             This exception occurs on parsing inputByteArray
     * @throws ResponseBuilderException
     *             All exceptions from <code>cMPMessageService.provide(pKIRequestMessage)</code> are being handled at EJB level, on handling these exceptions, an errorMessage is built. While building
     *             this errorMessage, ResponseBuilderException is thrown.
     */
    @POST
    @Path("/synch")
    public void processPkiMessageSynch(final byte[] inputByteArray, final @Suspend(60000) AsynchronousResponse response) throws CertificateParseException, InvalidCertificateVersionException,
            IOException, MessageParsingException, ResponseBuilderException {
        processPkisynchRequestMessage(inputByteArray, response, null);
    }

    /**
     * <P>
     * This method which will be invoked once REST URL is hit by the entity for CMP Request. There are two levels of exception handling, one is at EJB layer and other is at REST layer, all user defined
     * application exceptions like <code> validationException and TransactionIdException </code> are being handled at EJB level and an errorMessage is being formed. However in the POST method,
     * inputByteArray needs to be converted into a user-defined object <code>RequestMessage</code>. While parsing this byteArray, if there are any exceptions like
     * <code>CertificateParseException</code> etc these are directly thrown at REST and an HTTP ErrorCode is mapped.
     * 
     * 
     * @param issuerName
     *            Certificate Authority Name of the Node
     * @param inputByteArray
     *            This is PKIMessage which is received as a byteArray in HTTP Request.
     * @return restResponse This is the actual response which will be sent back to Node.Please refer to {@link PKIResponseToRestResponseMapper}  for http response being sent back to entity.
     * @throws CertificateParseException
     *             This exception occurs when Certificate inside PKIMessage can not be parsed properly. Occurs when inputByteArray is converted to RequestMessage object
     * @throws InvalidCertificateVersionException
     *             This exception occurs when certificate in RequestMessage is not of X509V3 version.
     * @throws IOException
     *             This exception occurs when inputByteArray is being converted to ASN1InputStream and in case the bytes could not be parsed properly.
     * @throws MessageParsingException
     *             This exception occurs on parsing inputByteArray
     * @throws ResponseBuilderException
     *             This exception is a wrapper exception for all other exceptions and is thrown in case of any exceptions while building Responses
     */
    @POST
    @Path("{issuerName}")
    public Response processPkiMessage(@PathParam("issuerName") final String issuerName, final byte[] inputByteArray) throws CertificateParseException, InvalidCertificateVersionException, IOException,
            MessageParsingException, ResponseBuilderException {
        return processPkiRequestMessage(inputByteArray, issuerName);
    }

    /**
     * <P>
     * This method which will be invoked once REST URL is hit by the entity for CMP Request. This is an "/synch" url, which is used by nodes which do not support Polling request. In this case, CMP
     * application will be sending directly IP response with USer certificate with no waiting status as an intermediate step. Asynchronous response is being used so that when response from PKI-Manager
     * is observed at RA side, this "Asynchronous response" object is set. This will not keep the EJB's engaged, once dispatched onto the queue, EJB will return back to the pool. Only REST service
     * will be kept engaged. There are two levels of exception handling, one at EJB layer and one at REST layer, all user defined application exception like
     * <code> validationException,TransactionIdException </code> are being handled at EJB level and an errorMessage is being formed. However in the POST method, inputByteArray needs to be converted
     * into a user-defined object <code>RequestMessage</code>. While parsing this byteArray, if there are any exceptions like <code>CertificateParseException</code> etc these are directly thrown at
     * REST and an HTTP ErrorCode is mapped.
     * 
     * 
     * @param issuerName
     *            Certificate Authority Name of the Node
     * @param inputByteArray
     *            This is PKIMessage which is sent as a byteArray in HTTP Request.
     * @param response
     *            This is the Asynchronous response(org.jboss.resteasy.spi.AsynchronousResponse)
     * @throws CertificateParseException
     *             This exception occurs when Certificate inside PKIMessage can not be parsed properly. Occurs when inputByteArray is converted to RequestMessage object
     * @throws InvalidCertificateVersionException
     *             This exception occurs when certificate in RequestMessage is not of X509V3 version.
     * @throws IOException
     *             This exception occurs when inputByteArray is being converted to ASN1InputStream and in case the bytes could not be parsed properly.
     * @throws MessageParsingException
     *             This exception occurs on parsing inputByteArray
     * @throws ResponseBuilderException
     *             All exceptions from <code>cMPMessageService.provide(pKIRequestMessage)</code> are being handled at EJB level, on handling these exceptions, an errorMessage is built. While building
     *             this errorMessage, ResponseBuilderException is thrown.
     */
    @POST
    @Path("{issuerName}/synch")
    public void processPkiMessageSynch(@PathParam("issuerName") final String issuerName, final byte[] inputByteArray, final @Suspend(60000) AsynchronousResponse response)
            throws CertificateParseException, InvalidCertificateVersionException, IOException, MessageParsingException, ResponseBuilderException {
        processPkisynchRequestMessage(inputByteArray, response, issuerName);
    }

    private Response processPkiRequestMessage(final byte[] inputByteArray, final String issuerName) throws MessageParsingException, CertificateParseException, InvalidCertificateVersionException,
            IOException {

        final boolean isRequest = true;
        byte[] signedCMPResponse = null;
        final RequestMessage pKIRequestMessage;
        String senderName = null;
        Response restResponse = null;

        pKIRequestMessage = new RequestMessage(inputByteArray);
        if (pKIRequestMessage.getSenderName().isEmpty()) {
             senderName = cMPMessageService.getSenderName(pKIRequestMessage);
            pKIRequestMessage.setSenderName(senderName);
        }
        pKIRequestMessage.setIssuerName(issuerName);

        logger.info("Started CMPService for processing : {} for entity {}", pKIRequestMessage.getRequestMessage(),senderName);
        final String pkiMessage = PKIMessageStringUtility.printPKIMessage(isRequest, pKIRequestMessage.getPKIMessage(), pKIRequestMessage.getBase64TransactionID());
        logger.debug("PKI Message {}", pkiMessage);

        signedCMPResponse = cMPMessageService.provide(pKIRequestMessage);

        restResponse = pKIResponseToRestResponseMapper.toRestResponse(signedCMPResponse);
        logger.info("Sent signed response from PKI-RA to entity ");

        systemRecorder.recordEvent("CMP_SERVICE.REQUEST_PROCESS_FINISHED", EventLevel.COARSE, "CMP_SERVICE.CREDENTIAL_ISSUE_OR_REISSUE", pKIRequestMessage.getSenderName(),
                pKIRequestMessage.getRequestMessage());

        return restResponse;
    }

    private void processPkisynchRequestMessage(final byte[] inputByteArray, final @Suspend(60000) AsynchronousResponse response, final String issuerName) throws MessageParsingException,
            CertificateParseException, InvalidCertificateVersionException, IOException {
        final boolean isRequest = true;
        final RequestMessage pKIRequestMessage;
        pKIRequestMessage = new RequestMessage(inputByteArray);
        pKIRequestMessage.setSyncRequest(true);

        pKIRequestMessage.setIssuerName(issuerName);
        final RestSynchResponse restAsynchResponse = new RestSynchResponse();
        restAsynchResponse.setAsyncResponse(response);

        logger.info("Started CMP Service for : {}", pKIRequestMessage.getRequestMessage());
        final String pkiMessage = PKIMessageStringUtility.printPKIMessage(isRequest, pKIRequestMessage.getPKIMessage(), pKIRequestMessage.getBase64TransactionID());
        logger.debug("PKI Message {}", pkiMessage);

        systemRecorder.recordEvent("CMP_SERVICE.ENROLLMENT_PROCESS_STARTED", EventLevel.COARSE, "CMP_SERVICE.CREDENTIAL_ISSUE_OR_REISSUE", pKIRequestMessage.getSenderName(),
                pKIRequestMessage.getRequestMessage());

        cMPMessageService.provide(pKIRequestMessage, restAsynchResponse);

        systemRecorder.recordEvent("CMP_SERVICE.ENROLLMENT_PROCESS_FINISHED", EventLevel.COARSE, "CMP_SERVICE.CREDENTIAL_ISSUE_OR_REISSUE", pKIRequestMessage.getSenderName(),
                pKIRequestMessage.getRequestMessage());
    }
}