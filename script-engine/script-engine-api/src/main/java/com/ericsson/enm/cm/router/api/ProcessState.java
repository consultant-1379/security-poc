package com.ericsson.enm.cm.router.api;

import java.io.Serializable;

public interface ProcessState extends Serializable {

    // TDO emulleo : rename to something better like Lifecyle?
    enum Code {
        COMPLETE, RUNNING
    }

    Code getCode();

    Integer getExitStatus();

    Integer getOutputLength();

    String getCommand();

    String getCommandSet();

    Boolean isSkipCache();
}
