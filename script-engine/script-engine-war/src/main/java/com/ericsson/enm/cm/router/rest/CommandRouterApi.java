
package com.ericsson.enm.cm.router.rest;

import static javax.ws.rs.core.Response.serverError;
import static javax.ws.rs.core.Response.status;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriInfo;

import org.jboss.resteasy.annotations.providers.multipart.MultipartForm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.codahale.metrics.Timer;
import com.ericsson.enm.cm.router.api.CommandRequest;
import com.ericsson.oss.services.cm.scriptengine.ejb.instrumentation.InstrumentationBean;
import com.ericsson.oss.services.cm.scriptengine.ejb.service.ScriptEngineCommandExecutor;
import com.ericsson.oss.services.scriptengine.rest.resources.file.FileHandler;
import com.ericsson.oss.services.scriptengine.rest.resources.file.FileRestResourceBean;
import com.ericsson.oss.services.scriptengine.spi.dtos.AbstractDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.ResponseDto;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@SuppressWarnings("PMD.AvoidCatchingThrowable")
@Path("/command")
public class CommandRouterApi {

    private static final Response http500InternalServerResponse = serverError().build();
    private static final Response http400BadRequestResponse = status(Status.BAD_REQUEST).build();

    @Inject
    private FileHandler fileHandler;

    @Context
    private UriInfo uriInfo;

    @Inject
    private InstrumentationBean instrumentationBean;

    @Inject
    private ScriptEngineCommandExecutor ScriptEngineCommandExecutor;

    @Inject
    FileRestResourceBean fileRestResourceBean;

    private final Logger logger = LoggerFactory.getLogger(CommandRouterApi.class);

    @POST
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public Response execute(@CookieParam("iPlanetDirectoryPro") final Cookie iPlanetDirectoryPro,
                            @MultipartForm final PostCommandRequestWithFile request,
                            @HeaderParam("X-Tor-UserID") final String userId)
            throws IOException {

        final String requestId;

        CommandRequest commandRequest = null;
        final Timer.Context timerContext = instrumentationBean.startMethodTimer(InstrumentationBean.REQUESTS_FROM_CLI);
        try {
            requestId = "";
            String filePath = null;
            if (request.hasFile()) {
                logger.info(" script-engine command with file={}", request.getFileName());
                filePath = fileHandler.write(request.getFileName(), request.getFile());
            }
            commandRequest = CommandRequest.fromCommandString(request.getCommand());
            commandRequest.setUserId(userId);
            commandRequest.setFilePath(filePath);
            commandRequest.setFileName(request.getFileName());
            commandRequest.setRequestId(requestId);

            final String requestIddd = "fakeRequestId";

            final List<AbstractDto> dtos = ScriptEngineCommandExecutor.processCommandRequest(commandRequest, requestIddd);

            final ObjectMapper objectMapper = new ObjectMapper();
            final JsonNode jsonNode = objectMapper.valueToTree(new ResponseDto(dtos));

            //             if command with file download
            String fileId = "";
            String applicationId = "";
            for (final JsonNode el : jsonNode.get("elements")) {
                if (el.get("dtoType").textValue().equals("fileDownload")) {
                    fileId = el.get("fileId").textValue();
                    applicationId = el.get("applicationId").textValue();
                    return fileRestResourceBean.downloadFile(applicationId, fileId);
                }
            }
            return Response.created(uriInfo.getAbsolutePath()).entity(jsonNode.get("elements").toString()).build();

        } catch (final Throwable t) {
            return http500InternalServerResponse;
        } finally {
            timerContext.stop();
        }

    }

    private String generateRequestIdForNotWebCliUsers(final boolean streaming) {
        String requestId = UUID.randomUUID().toString();
        if (streaming) {
            requestId = "st:" + requestId;
        }
        return requestId;
    }

}
