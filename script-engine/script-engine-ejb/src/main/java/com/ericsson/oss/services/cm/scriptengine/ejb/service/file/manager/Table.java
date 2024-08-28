
package com.ericsson.oss.services.cm.scriptengine.ejb.service.file.manager;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.services.scriptengine.spi.dtos.AbstractDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.LineDto;

public class Table {
    private final List<AbstractDto> headerDtos = new ArrayList<AbstractDto>();
    private final List<AbstractDto> rowDtos = new ArrayList<AbstractDto>();

    public Table(final AbstractDto header) {
        headerDtos.add(new LineDto());
        headerDtos.add(header);
    }

    public void addRow(final AbstractDto row) {
        // Don't check for duplicates
        rowDtos.add(row);
    }

    public List<AbstractDto> getTableHeaderDtos() {
        return headerDtos;
    }

    public List<AbstractDto> getTableRowsDtos() {
        return rowDtos;
    }
}
