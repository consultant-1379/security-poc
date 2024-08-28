package com.ericsson.oss.services.cm.scriptengine.ejb.service.stubunittest;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import com.ericsson.enm.cm.router.api.CommandRequest;
import com.ericsson.oss.itpf.sdk.eventbus.Channel;
import com.ericsson.oss.itpf.sdk.eventbus.Event;
import com.ericsson.oss.itpf.sdk.eventbus.EventConfigurationBuilder;
import com.ericsson.oss.itpf.sdk.eventbus.annotation.Consumes;
import com.ericsson.oss.itpf.sdk.eventbus.annotation.Endpoint;
import com.ericsson.oss.services.scriptengine.spi.dtos.AbstractDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandResponseDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.LineDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.summary.SummaryDto;

/**
 * Class CommandResponderEmulator is a stub used to ensure communication between script-engine and jms works as expected. All commands that wish to
 * work asynchronously can use the commandHandler.&lt;commandSet&gt; mechanism for queue naming. This allows script-engine to find the queue and send
 * the message to it.
 */
@ApplicationScoped
public class CommandResponderEmulator {

    @Inject
    @Endpoint(value = "jms:/queue/scriptengine/output", timeToLive = 1800000)
    private Channel scriptEngineOutputChannel;

    /**
     * Receives {@link CommandRequest} from script-engine for the cmedit commandSet where the command is 'cmedit get' or 'cmedit describe'.
     *
     * @param event
     *            contains the {@link CommandRequest}.
     */
    public void recieveCommandRequest(@Observes @Consumes(endpoint = "jms:queue/commandHandler.cmedit", filter = "command IN ('get', 'describe', 'version')") final Event event) {
        final CommandRequest commandRequest = (CommandRequest) event.getPayload();
        final String requestId = event.getCorrelationId();
        respondToRequest(requestId, commandRequest);
    }

    public void recieveInvalidCommandRequest(@Observes @Consumes(endpoint = "jms:queue/commandHandler.cmedit", filter = "command<>'get' AND command<>'describe'") final Event event) {
        final CommandRequest commandRequest = (CommandRequest) event.getPayload();
        final String requestId = event.getCorrelationId();
        final CommandResponseDto commandResponseDto = createCommandResponseDtoForCommand(commandRequest);
        commandResponseDto.setStatusCode(-1);
        commandResponseDto.setErrorCode(4001);
        commandResponseDto.setErrorMessage("Command syntax error, cannot resolve the cmedit command");
        commandResponseDto.addErrorLines();
        sendToScriptEngineOutputChannel(requestId, true, convertToArrayOfAbstractDtos(commandResponseDto));
    }

    /**
     * @param requestId
     * @param commandRequest
     */
    private void respondToRequest(final String requestId, final CommandRequest commandRequest) {
        final String command = commandRequest.getCommandSet() + " " + commandRequest.getCommandWithArguments();
        final CommandDto commandDto = new CommandDto(command);
        final List<AbstractDto> lines = getResponseLines(command);
        final String statusMessage = lines.size() + " instance(s)";
        final List<AbstractDto> summaries = getSummaries(command, statusMessage, requestId);
        final LineDto statusMessageDto = new LineDto(statusMessage);
        if (isSingleResponse(command)) {
            final List<AbstractDto> response = new ArrayList<>();
            response.add(commandDto);
            response.addAll(lines);
            response.add(statusMessageDto);
            if (commandRequest.isStreaming()) {
                response.add(summaries.get(0));
            }
            sendToScriptEngineOutputChannel(requestId, true, toArray(response));
        } else {
            sendToScriptEngineOutputChannel(commandRequest.getRequestId(), false, new AbstractDto[] { commandDto });
            final long responseDelay = getResponseDelay(command);
            waitFor(responseDelay);
            for (final AbstractDto line : lines) {
                sendToScriptEngineOutputChannel(commandRequest.getRequestId(), false, new AbstractDto[] { line });
                waitFor(responseDelay);
            }
            if (commandRequest.isStreaming()) {
                sendToScriptEngineOutputChannel(commandRequest.getRequestId(), false, new AbstractDto[] { statusMessageDto });
                for (final AbstractDto summary : summaries) {
                    sendToScriptEngineOutputChannel(requestId, true, new AbstractDto[] { summary });
                }
            } else {
                sendToScriptEngineOutputChannel(requestId, true, new AbstractDto[] { statusMessageDto });
            }
        }
    }

    private void waitFor(final long responseDelay) {
        try {
            Thread.sleep(responseDelay);
        } catch (final InterruptedException e) {
        }
    }

    private AbstractDto[] toArray(final List<AbstractDto> dtos) {
        if (dtos == null || dtos.isEmpty()) {
            return new AbstractDto[0];
        }
        return dtos.toArray(new AbstractDto[dtos.size()]);
    }

    private List<AbstractDto> getResponseLines(final String command) {
        final List<AbstractDto> lines = new ArrayList<>();
        final int numLines = getNumberOfLines(command);
        for (int i = 0; i < numLines; i++) {
            lines.add(new LineDto("Line: " + i));
        }
        return lines;
    }

    private List<AbstractDto> getSummaries(final String command, final String statusMessage, final String requestId) {
        final List<AbstractDto> summaries = new ArrayList<>();
        final int numSummaries = getNumberOfSummaries(command);
        for (int i = 0; i < numSummaries; i++) {
            summaries.add(new SummaryDto(statusMessage, 0, null, null, requestId));
        }
        return summaries;
    }

    private CommandResponseDto createCommandResponseDtoForCommand(final CommandRequest commandRequest) {
        final String commandWithArguments = commandRequest.getCommandWithArguments();
        final String command = commandRequest.getCommandSet() + " " + commandRequest.getCommandWithArguments();
        final int numLines = getNumberOfLines(commandWithArguments);
        final String statusMessage = numLines + " instance(s)";
        final CommandResponseDto commandResponseDto = new CommandResponseDto();
        final List<AbstractDto> dtos = commandResponseDto.getResponseDto().getElements();
        dtos.add(new CommandDto(command));
        commandResponseDto.setCommand(command);
        commandResponseDto.setStatusCode(0);
        commandResponseDto.setStatusMessage(statusMessage);
        for (int i = 1; i <= numLines; i++) {
            if (commandRequest.isStreaming()) {
                final LineDto line = new LineDto("Line: " + i);
                final AbstractDto[] partialDtos = new AbstractDto[] { line };
                sendToScriptEngineOutputChannel(commandRequest.getRequestId(), false,partialDtos);
                try {
                    Thread.sleep(2000);
                } catch (final InterruptedException e) {
                }
            } else {
                commandResponseDto.addLine("Line: " + i);
            }
        }
        commandResponseDto.addSuccessLines();
        if (commandRequest.isStreaming()) {
            dtos.add(new SummaryDto(statusMessage, 0, null, null, commandRequest.getRequestId()));
        }
        return commandResponseDto;
    }

    private void sendToScriptEngineOutputChannel(final String requestId, final boolean terminate, final AbstractDto[] dtos) {
        EventConfigurationBuilder eventConfigurationBuilder = new EventConfigurationBuilder();
        if (terminate) {
            eventConfigurationBuilder.addEventProperty("terminate", "true");
        } else {
            if (isCacheToFile(requestId)) {
                eventConfigurationBuilder = eventConfigurationBuilder.addEventProperty("cacheToFile", "true");
            }
            eventConfigurationBuilder = eventConfigurationBuilder.addEventProperty("skipCache", "true");
        }
        final Event event = scriptEngineOutputChannel.createEvent(dtos, requestId);
        scriptEngineOutputChannel.send(event, eventConfigurationBuilder.build());
    }

    private boolean isCacheToFile(final String requestId) {
        return (requestId.startsWith("st:file:"));
    }

    private AbstractDto[] convertToArrayOfAbstractDtos(final CommandResponseDto commandResponseDto) {
        final List<AbstractDto> dtos = commandResponseDto.getResponseDto().getElements();
        return dtos.toArray(new AbstractDto[dtos.size()]);
    }

    private static int getNumberOfLines(final String command) {
        final Pattern pattern = Pattern.compile(".*lines=(\\d+).*");
        final Matcher matcher = pattern.matcher(command);
        if (matcher.matches()) {
            final String val = matcher.group(1);
            return Integer.parseInt(val.trim());
        }
        return 0;
    }

    private static int getNumberOfSummaries(final String command) {
        final Pattern pattern = Pattern.compile(".*summaries=(\\d+).*");
        final Matcher matcher = pattern.matcher(command);
        if (matcher.matches()) {
            final String val = matcher.group(1);
            return Integer.parseInt(val.trim());
        }
        return 1;
    }

    private static boolean isSingleResponse(final String command) {
        final Pattern pattern = Pattern.compile(".*single=(true|false).*");
        final Matcher matcher = pattern.matcher(command);
        if (matcher.matches()) {
            final String val = matcher.group(1);
            return Boolean.parseBoolean(val.trim());
        }
        return false;
    }

    private static long getResponseDelay(final String command) {
        final Pattern pattern = Pattern.compile(".*responseDelay=(\\d+).*");
        final Matcher matcher = pattern.matcher(command);
        if (matcher.matches()) {
            final String val = matcher.group(1);
            return Long.parseLong(val.trim());
        }
        return 0;
    }
}
