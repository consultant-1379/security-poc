
package com.ericsson.oss.services.cm.scriptengine.ejb.service.file;


import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.LocalBean;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerService;
import javax.inject.Inject;

@Singleton
@LocalBean
@Startup
public class FileCleanupTimerBean {

    @Resource
    private TimerService timerService;

    @Inject
    private FileHandlerBean fileHandlerBean;

    private static final String UNIX_FILE_PATH = "/ericsson/config_mgt/script_engine";

    @PostConstruct
    public void setupTimer() {
        timerService.createTimer(TimeUnit.MINUTES.toMillis(10), TimeUnit.MINUTES.toMillis(15), "ScriptEngineCacheToFile_Cleanup_Timer");
    }

    @Timeout
    public void fileCleanup(final Timer timer) {
        // remove file for outputToFile feature
        fileHandlerBean.cleanupDirectoriesAndFiles(fileHandlerBean.getOutputToFileDownloadDirectoryPath(), TimeUnit.MINUTES.toMillis(60));
        // remove file for rest application
        fileHandlerBean.purgeOlderFiles(UNIX_FILE_PATH, TimeUnit.MINUTES.toMillis(30) );

        // remove RestEasy Files from /tmp
        fileHandlerBean.purgeOlderRestEasyFiles(TimeUnit.MINUTES.toMillis(30) );
    }

}
