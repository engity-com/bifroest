import type { GridColDef, GridFilterModel, GridValidRowModel } from '@mui/x-data-grid';
import type { ColumnFilter } from '../management/protocol';

export interface GridSearch {
    readonly query: string;
    readonly filter: ColumnFilter | null;
}
export function gridSearch<R extends GridValidRowModel>(
    model: GridFilterModel,
    columns: readonly GridColDef<R>[],
): GridSearch {
    const query = (model.quickFilterValues ?? []).map(String).join(' ').slice(0, 256);
    const item = model.items[0];
    const column = columns.find((column) => column.field === item?.field);
    if (!item || !column || column.filterable === false) {
        return { query, filter: null };
    }
    const operator = column.filterOperators?.find((operator) => operator.value === item.operator);
    if (
        operator?.requiresFilterValue === false ||
        item.operator === 'isEmpty' ||
        item.operator === 'isNotEmpty'
    ) {
        return { query, filter: { field: item.field, operator: item.operator, value: '' } };
    }
    if (
        item.value === undefined ||
        item.value === null ||
        item.value === '' ||
        (Array.isArray(item.value) && item.value.length === 0)
    ) {
        return { query, filter: null };
    }
    let value = String(item.value);
    if (item.operator === 'isAnyOf') {
        if (!Array.isArray(item.value) || item.value.length > 16) {
            throw new Error('filter-limit');
        }
        if (item.value.some((value) => new TextEncoder().encode(String(value)).byteLength > 256)) {
            throw new Error('filter-limit');
        }
        value = JSON.stringify(item.value.map(String));
    } else if (column.type === 'dateTime') {
        const date = new Date(value);
        if (!Number.isFinite(date.getTime())) {
            return { query, filter: null };
        }
        date.setSeconds(0, 0);
        value = date.toISOString();
    }
    if (new TextEncoder().encode(value).byteLength > 2048) {
        throw new Error('filter-limit');
    }
    return { query, filter: { field: item.field, operator: item.operator, value } };
}
export function gridModel(query: string, filter: ColumnFilter | null): GridFilterModel {
    return {
        items: filter
            ? [
                  {
                      id: 1,
                      field: filter.field,
                      operator: filter.operator,
                      ...(filter.value !== ''
                          ? {
                                value:
                                    filter.operator === 'isAnyOf'
                                        ? (JSON.parse(filter.value) as string[])
                                        : filter.value,
                            }
                          : {}),
                  },
              ]
            : [],
        quickFilterValues: query.split(/\s+/u).filter(Boolean),
    };
}
