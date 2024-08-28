
package com.ericsson.oss.services.cm.scriptengine.ejb.service.file.manager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.inject.Inject;

import com.ericsson.oss.services.cm.scriptengine.ejb.service.file.FileHandlerBean;
import com.ericsson.oss.services.scriptengine.spi.dtos.AbstractDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.HeaderRowDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.RowDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.TextPlainFormatter;
import com.ericsson.oss.services.scriptengine.spi.dtos.confirmation.ConfirmationDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.summary.SummaryDto;
import com.google.common.collect.FluentIterable;

public class DtoCacheToFileManager {

    @Inject
    private FileHandlerBean fileHandlerBean;

    private boolean isTableFormat = false;

    private final Map<Integer, Table> tables = new LinkedHashMap<>();

    private String requestId = null;

    private List<AbstractDto> dtos = null;

    private List<AbstractDto> terminateDtosForTable = null;

    private final TextPlainFormatter formatter = new TextPlainFormatter("");

    private boolean terminate = false;

    public final static String IS_TERMINATE = "isTerminate";

    public final static String IS_CONFIRMATION_RESPONSE = "isConfirmationResponse";

    @SuppressWarnings("PMD.UnnecessaryConstructor")
    public DtoCacheToFileManager() {

    }

    public Map<String, Boolean> writeDtosToFile(final AbstractDto[] dtos, final String requestId) {
        final Map<String, Boolean> statusInfo = new HashMap<String, Boolean>();
        statusInfo.put(IS_TERMINATE, false);
        statusInfo.put(IS_CONFIRMATION_RESPONSE, false);
        if (dtos == null || dtos.length == 0) {
            return statusInfo;
        }
        this.dtos = new ArrayList<AbstractDto>(Arrays.asList(dtos));
        terminateDtosForTable = new ArrayList<AbstractDto>();

        if (dtosContainCommandDto() && this.dtos.size() == 1) {
            return statusInfo;
        }
        this.requestId = requestId;
        tables.clear();
        isTableFormat = isTableFormat();
        terminate = isTerminate();
        statusInfo.put(IS_TERMINATE, terminate);
        statusInfo.put(IS_CONFIRMATION_RESPONSE, isConfirmationResponse());
        extractTableData();
        writeDtosToFile();
        return statusInfo;
    }

    /*
     * P R I V A T E - M E T H O D S
     */
    private boolean dtosContainCommandDto() {
        return FluentIterable.from(dtos)
                .filter(CommandDto.class)
                .first().isPresent();
    }

    private boolean isTableFormat() {
        return FluentIterable.from(dtos)
                .filter(HeaderRowDto.class)
                .first().isPresent();
    }

    private boolean isTerminate() {
        return FluentIterable.from(dtos)
                .filter(SummaryDto.class)
                .first().isPresent();
    }

    private boolean isConfirmationResponse() {
        return FluentIterable.from(dtos).filter(ConfirmationDto.class).first().isPresent();
    }

    private void extractTableData() {
        if (isTableFormat) {
            // message dtos can contain multiple tables
            Integer currentTableHashCode = null;
            for (final AbstractDto dto : dtos) {
                if (dto instanceof HeaderRowDto) {
                    currentTableHashCode = new Integer(dto.hashCode());
                    addHeader(currentTableHashCode, dto);
                } else if (dto instanceof RowDto) {
                    addRow(currentTableHashCode, dto);
                } else {
                    terminateDtosForTable.add(dto);
                }
            }
        }
    }

    private void writeDtosToFile() {
        if (isTableFormat) {
            writeToFileWithTableFormat();
        } else {
            writeToFileWithLineFormat();
        }
    }

    private void addHeader(final Integer currentTableHashCode, final AbstractDto header) {
        if (!tables.containsKey(currentTableHashCode)) {
            tables.put(currentTableHashCode, new Table(header));
        }
    }

    private void addRow(final Integer currentTableHashCode, final AbstractDto row) {
        if (tables.containsKey(currentTableHashCode)) {
            tables.get(currentTableHashCode).addRow(row);
        }
    }

    private void writeToFileWithLineFormat() {
        final String filePath = getFinalFilePath(requestId);
        // TODO: epaulki instrument bytes written to file.
        fileHandlerBean.writeFile(filePath, formatter.format(dtos).getBytes());
    }

    private void writeToFileWithTableFormat() {
        // Check is the response is in a single response message
        boolean singleResponse = false;
        if (terminate && !fileHandlerBean.exists(getDiretoryPath(requestId))) {
            singleResponse = true;
        }

        if (terminate) {
            final String filePath = getFinalFilePath(requestId);
            fileHandlerBean.writeFile(filePath, formatter.format(terminateDtosForTable).getBytes());
        }

        int orderedFileName = 1;
        for (final Entry<Integer, Table> tableEntry : tables.entrySet()) {
            final Integer headerHashCode;
            if (singleResponse) {
                headerHashCode = orderedFileName;
                orderedFileName++;
            } else {
                headerHashCode = tableEntry.getKey();
            }
            final Table table = tableEntry.getValue();
            final String headerFilePath = getTableHeaderFilePath(requestId, headerHashCode);
            if (!fileHandlerBean.exists(headerFilePath)) {
                fileHandlerBean.writeFile(headerFilePath, formatter.format(table.getTableHeaderDtos()).getBytes());
            }
            final String rowFilePath = getTableRowFilePath(requestId, headerHashCode);
            fileHandlerBean.writeFile(rowFilePath, formatter.format(table.getTableRowsDtos()).getBytes());
        }
    }

    private String getTableHeaderFilePath(final String requestId, final int hashCode) {
        return getDiretoryPath(requestId) + hashCode + "_header";
    }

    private String getTableRowFilePath(final String requestId, final int hashCode) {
        return getDiretoryPath(requestId) + hashCode + "_rows";
    }

    private String getFinalFilePath(final String requestId) {
        return getDiretoryPath(requestId) + "final";
    }

    private String getDiretoryPath(final String requestId) {
        return fileHandlerBean.getOutputToFileDownloadDirectoryPath() + requestId + "/";
    }
}
