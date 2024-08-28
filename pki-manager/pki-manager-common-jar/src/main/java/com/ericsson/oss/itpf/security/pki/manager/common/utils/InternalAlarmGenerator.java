/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.utils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.client.ClientResponse;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.CertExpiryNotificationsConstants;
import com.ericsson.oss.services.fm.internalalarm.api.InternalAlarmRequest;

/**
 * This class generates FM alarm to notify expiration of CA or Entity certificates
 */

public class InternalAlarmGenerator {

    private final static String url = "http://internalalarm-service:8080/internal-alarm-service/internalalarm/internalalarmservice/translate";

    @Inject
    private Logger logger;

    @Inject
    protected SystemRecorder systemRecorder;

    /**
     * This method raise an FM alarm for the certificate expire of CA or Entity.
     * 
     * @param alarmDetails
     *            Map containing alarm details need to be generated
     */
    public void raiseInternalAlarm(final Map<String, Object> alarmDetails) {

        try {

            final InternalAlarmRequest internalAlarmRequest = generateRequestObject(alarmDetails);
            final ClientRequest request = new ClientRequest(url);
            request.accept(MediaType.APPLICATION_JSON);
            final String jsonRequest = getJsonString(internalAlarmRequest);
            request.body(MediaType.APPLICATION_JSON, jsonRequest);
            request.header("host","internalalarm-service");
            logger.debug("json request which is sent to Alarmendpoint {}", jsonRequest);

            logger.info("Raising an internal alarm for {} with serial number {}  ", (String) alarmDetails.get(CertExpiryNotificationsConstants.NAME),
                    alarmDetails.get(CertExpiryNotificationsConstants.SERIAL_NUMBER));
            final ClientResponse<String> response = request.post(String.class);

            if (response.getStatus() == Response.Status.OK.getStatusCode()) {
                logger.info("Alarm request processed successfully for {} ", (String) alarmDetails.get(CertExpiryNotificationsConstants.NAME));
            } else {
                logger.info("Alarm request failed for {} ", (String) alarmDetails.get(CertExpiryNotificationsConstants.NAME));
            }
        } catch (Exception exception) {
            systemRecorder.recordError(CertExpiryNotificationsConstants.INTERNAL_ALARM_ERROR_ID, ErrorSeverity.NOTICE, CertExpiryNotificationsConstants.SOURCE,
                    (String) alarmDetails.get(CertExpiryNotificationsConstants.NAME), (String) alarmDetails.get(CertExpiryNotificationsConstants.PROBABLE_CAUSE));
            logger.error("Failed to raise alarm {}", exception.getMessage());
        }
    }

    private InternalAlarmRequest generateRequestObject(final Map<String, Object> alarmDetails) {

        final InternalAlarmRequest internalAlarmRequest = new InternalAlarmRequest();
        internalAlarmRequest.setEventType((String) alarmDetails.get(CertExpiryNotificationsConstants.EVENT_TYPE));
        internalAlarmRequest.setProbableCause((String) alarmDetails.get(CertExpiryNotificationsConstants.PROBABLE_CAUSE));
        internalAlarmRequest.setSpecificProblem((String) alarmDetails.get(CertExpiryNotificationsConstants.SPECIFIC_PROBLEM));
        internalAlarmRequest.setPerceivedSeverity((String) alarmDetails.get(CertExpiryNotificationsConstants.PERCEIVED_SEVERITY));
        internalAlarmRequest.setRecordType((String) alarmDetails.get(CertExpiryNotificationsConstants.RECORD_TYPE));
        internalAlarmRequest.setManagedObjectInstance((String) alarmDetails.get(CertExpiryNotificationsConstants.MANAGED_OBJECT_INSTANCE));

        final Map<String, String> additionalAttributes = new HashMap<>();
        additionalAttributes.put(CertExpiryNotificationsConstants.PROBLEM_TEXT,
                (String) alarmDetails.get(CertExpiryNotificationsConstants.PROBLEM_TEXT));
        internalAlarmRequest.setAdditionalAttributes(additionalAttributes);

        return internalAlarmRequest;
    }

    private String getJsonString(final InternalAlarmRequest internalAlarmRequest) throws JsonGenerationException, JsonMappingException, IOException {
        final ObjectMapper mapper = new ObjectMapper();
        String jsonRequest = null;
        jsonRequest = mapper.writeValueAsString(internalAlarmRequest);
        return jsonRequest;
    }
}
