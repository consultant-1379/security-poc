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
package com.ericsson.oss.itpf.security.pki.ra.scep.resources;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.scep.api.*;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.Operation;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.*;

/**
 * ScepRestService accepts all the SCEP Protocol related requests from SCEP client. This class has the methods to accept requests over http get and post methods and calls the appropriate methods to
 * process those requests.
 *
 * @author xtelsow
 */
@Path("/")
public class PkiScepRestService {
    @Inject
    private Logger logger;
    @EServiceRef
    private PkiScepService pkiScepService;
    @Inject
    private PkiScepRequest pkiScepRequest;
    @Inject
    private PkiResponseToRestResponseMapper pkiResponseToRestResponseMapper;
    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method will get the SCEP Request message from SCEP Client through restful GET operation to process SCEP Message.
     *
     * @URL http://<<hostname>:<<port>>/pkira-scep/caname?operation=GetCACert&message =test.
     * @param caName
     *            to fetch the corresponding CA/RA Certificates from key store.
     * @param operation
     *            the operation value to know which SCEP related operation to perform.
     * @param message
     *            PKI message from SCEP client.
     * @return Response is the corresponding SCEP Response message to be sent to the SCEP Client after processing the SCEP Request message.
     * @throws ProtocolException
     *             is a super class for all the user defined exception and will be thrown while processing SCEP operations.
     */
    @GET
    @Path("{caname}")
    @Consumes("*/*")
    @Produces(MediaType.TEXT_HTML)
    public Response processScepMessage(@PathParam("caname") final String caName, @QueryParam("operation") final String scepOperation, @QueryParam("message") String message) throws ProtocolException {
        logger.debug("processScepMessage get method in ScepRestService class");
        final Operation operation = getValidScepOperation(caName, scepOperation, false);
        message = message.replace(" ", "+");
        logger.debug("End of processScepMessage get method in ScepRestService class");
        return processMessage(caName, message, operation, false);

    }

    /**
     * This method will get the SCEP Request message from SCEP Client through restful POST operation to process SCEP Message.
     *
     * @URL http://<<host name>>:<<port>>/pkira-scep/caname
     * @param caName
     *            to fetch the corresponding CA and RA certificates.
     * @Param message is the SCEP Request message from SCEP Client.
     * @return Response is the corresponding SCEP Response message to be sent to the SCEP Client after processing the SCEP Request message.
     * @throws ProtocolException
     *             is a super class for all the user defined exception and will be thrown while processing SCEP operations.
     */

    @POST
    @Path("{caname}")
    @Consumes("*/*")
    @Produces(MediaType.TEXT_HTML)
    public Response processScepMessage(@PathParam("caname") final String caName, final byte[] message) throws ProtocolException {
        logger.debug("processScepMessage post method in ScepRestService class");
        final String msg = new String(message);
        return processMessage(caName, msg, Operation.PKIOPERATION, false);
    }

    /**
     * This method will get the SCEP Request message from SCEP Client through restful GET operation to process SCEP Message.
     *
     * @URL http://<<hostname>:<<port>>/pkira-scep/trust/caname?operation=GetCACert&message =test.
     * @param caName
     *            to fetch the corresponding trust certificates from trust store.
     * @param operation
     *            the operation value to know which SCEP related operation to perform.
     * @param message
     *            PKI message from SCEP client.
     * @return Response is the corresponding SCEP Response message to be sent to the SCEP Client after processing the SCEP Request message.
     * @throws ProtocolException
     *             is a super class for all the user defined exception and will be thrown while processing SCEP operations.
     */
    @GET
    @Path("trust/{caname}")
    @Consumes("*/*")
    @Produces(MediaType.TEXT_HTML)
    public Response processScepMessage(@PathParam("caname") final String caName, @QueryParam("operation") final String scepOperation) throws ProtocolException {
        logger.info("processScepMessage method in ScepRestService class to get trust certificates with caname {}, operation {}", caName, scepOperation);
        final Operation operation = getValidScepOperation(caName, scepOperation, true);
        return processMessage(caName, "", operation, true);
    }

    private Operation getValidScepOperation(final String caName, final String scepOperation, final boolean isTrust) {
        Operation operation = null;
        if (scepOperation == null) {
            logger.error("Invalid SCEP Operation is present in the URL");
            systemRecorder.recordError("PKI_RA_SCEP.SCEP_OPERATION", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollement For EndEntity",
                    "Operation should not be empty in the URL for SCEP Enrollment for CA Name :" + caName);
            throw new BadRequestException(ErrorMessages.EMPTY_OPERATION);
        }
        for (final Operation operationValue : Operation.values()) {
            if (operationValue.getScepOperation().equalsIgnoreCase(scepOperation)) {
                if (isTrust) {
                    if (scepOperation.equalsIgnoreCase(Operation.GETCACERT.getScepOperation()) || scepOperation.equalsIgnoreCase(Operation.GETCACERTCHAIN.getScepOperation())) {
                        operation = operationValue;
                    }
                } else {
                    operation = operationValue;
                }
                break;
            }
        }
        if (operation == null) {
            logger.error(ErrorMessages.UNSUPPORTED_SCEP_OPERATION);
            systemRecorder.recordError("PKI_RA_SCEP.SCEP_OPERATION", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollement For EndEntity", "Invalid SCEP Operation is present in the URL for CA Name :"
                    + caName);
            throw new BadRequestException(ErrorMessages.UNSUPPORTED_SCEP_OPERATION);
        }
        return operation;
    }

    /**
     * This method sets the input values to pkiScepRequest and sends it to corresponding handler to process the request. The appropriate response is returned after processing the PKI-Message. For this
     * purpose, this method invokes toResponse method of mapper class to map PKI Response to Rest Response.
     *
     * @param caName
     *            to fetch the corresponding CA and RA Certificates.
     * @param message
     *            is the SCEP Request message from SCEP client.
     * @param scepOperation
     *            the operation value to know which SCEP operation to perform.
     * @return Response is the corresponding SCEP Response message to be sent to the SCEP Client after processing the SCEP Request message."
     *
     * @throws ProtocolException
     *             is a super class for all the user defined exception and will be thrown while processing SCEP operations.
     */
    private Response processMessage(final String caName, final String message, final Operation scepOperation, final boolean isReadFromTrustStore) throws ProtocolException {
        logger.debug("processMessage method in ScepRestService class");
        if (Operation.PKIOPERATION.equals(scepOperation)) {
            if (message == null || message.isEmpty()) {
                logger.error("Message should not be empty in the URL");
                systemRecorder.recordError("PKI_RA_SCEP.SCEP_MESSAGE", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollement For EndEntity",
                        "Invalid SCEP request from end entity: Message should not be empty in the URL for CA Name :" + caName);
                throw new BadRequestException(ErrorMessages.EMPTY_MESAGE);
            }
            pkiScepRequest.setMessage(message.getBytes());
        }
        pkiScepRequest.setCaName(caName);
        pkiScepRequest.setOperation(scepOperation);
        pkiScepRequest.setReadFromTrustStore(isReadFromTrustStore);
        if (pkiScepService == null) {
            logger.error("Unable to inject pkiScepService");
            throw new PkiScepServiceException(ErrorMessages.REQUEST_PROCESS_FAILURE);
        }

        final PkiScepResponse pkiScepResponse = pkiScepService.handleRequest(pkiScepRequest);

        if (pkiScepResponse.getContentType() == null || pkiScepResponse.getMessage() == null) {
            logger.error("Either ContenType or Response Message is not present");
            systemRecorder.recordError("PKI_RA_SCEP.SCEP_RESPONSE_MESSAGE", ErrorSeverity.ERROR, "PKIRASCEPService", "SCEP Enrollement For EndEntity",
                    "Either ContenType or Response Message is not present in PKCS7 SCEP response message for CA Name :" + caName);
            throw new PkiScepServiceException(ErrorMessages.RESPONSE_BUILD_FAILURE);
        }
        logger.debug("End of processMessage method in ScepRestService class");
        return pkiResponseToRestResponseMapper.toRestResponse(pkiScepResponse);
    }

}
