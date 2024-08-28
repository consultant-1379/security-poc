
package com.ericsson.oss.services.scriptengine.rest.resources;

import javax.inject.Inject;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;

public class CommandRouterApiParameterChecker {

    @Inject
    private SystemRecorder systemRecorder;

    // M E T H O D S - I N V A L I D
    public boolean getInputsAreInvalid(final String requestId, final String message) {
        return requestIdIsInvalid(requestId, message);
    }

    public boolean getTextPlainInputsAreInvalid(final String requestId, final String userFilename, final String message) {
        return requestIdIsInvalid(requestId, message) || userFilenameIsInvalid(userFilename, message);
    }

    // R E C O R D - E R R O R S
    public void recordHttp400BadRequestError(final String source, final String callingMethod) {
        systemRecorder.recordError("400 Bad Request", ErrorSeverity.ERROR, "CM CLI REST Client", source,
                "Invalid input for parameter " + source + " in " + callingMethod + ".");
    }

    public void recordHttp500InternalServerError(final String source, final String callingMethod) {
        systemRecorder.recordError("500 Internal Server Error", ErrorSeverity.ERROR, "CM CLI REST Client", source,
                callingMethod);
    }

    // P A R A M E T E R S - I N V A L I D
    private boolean requestIdIsInvalid(final String requestId, final String message) {
        if (requestId == null || requestId.equalsIgnoreCase("null")) {
            recordHttp400BadRequestError("requestId", message);
            return true;
        }
        return false;
    }

    private boolean userFilenameIsInvalid(final String userFilename, final String message) {
        if (userFilename != null && userFilename.contains("/")) {
            recordHttp400BadRequestError("userFilename", message);
            return true;
        }
        return false;
    }
}
