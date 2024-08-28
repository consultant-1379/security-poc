
package com.ericsson.oss.services.scriptengine.rest.resources.file;

import java.util.List;

import com.google.common.collect.Lists;

public class FilePathAccessChecker {

    // TODO EEITSIK, EGARCOL This whole class should be removed, bugs need to be written on any application using paths as part of their URL
    final static List<String> accessiblePaths = Lists.newArrayList(
            "/ericsson/batch/data/export/3gpp_export/",
            "/ericsson/batch/data/export/dynamic_export/",
            "/ericsson/batch/undo/",
            "/ericsson/netlog/export/",
            "/ericsson/tor/data/shm/",
            "/ericsson/tor/no_rollback/fmexport/data/",
            "/ericsson/tor/data/nodecli/",
            "/ericsson/tor/data/nodecli/cmdlist/",
            "/ericsson/tor/data/nodecli/results/");

    final static List<String> applicationIdsWithSecureFileDownloadHandlers = Lists.newArrayList(
            "ap",
            "pkiadm",
            "lcmadm",
            "exportNetlog",
            "exportReportDownloader",
            "exportCompareReportDownloader",
            "viewAcFileDownloader",
            "pushServiceKeyExport");

    /*
     * TODO The best solution would be to have each applicationId and path in a Map, then if the applicationId maps to the path allow access. Since we
     * are finding it hard to get the path never mind the appId we should probably just check the path.
     */
    public boolean isAccessible(final String filePath) {
        for (final String accessiblePath : accessiblePaths) {
            if (filePath.startsWith(accessiblePath)) {
                return true;
            }
        }
        return false;
    }

    public boolean isDownloadPermitted(final String applicationId, final String fileId) {
        return applicationIdsWithSecureFileDownloadHandlers.contains(applicationId) || isAccessible(fileId);
    }
}
