

def get_ordering_vars(query_params, default_column=None, default_direction=''):
    """
    Returns column and direction to order/sort a datatable. Reads from requests query params, as posted
    by Datatables AJAX calls
    :return: Column and direction. Column = None indicates no ordering
    """
    if 'order[0][column]' in query_params and 'order[0][dir]' in query_params:
        order_by_column = query_params['columns[{idx}][data]'.format(idx=str(query_params['order[0][column]']))]
        #if order_by_column == 'short_filename':
        #    order_by_column = 'filename'
        #if order_by_column == 'short_ftype':
        #    order_by_column = 'ftype'
        #if order_by_column == "notifyonhit":  # changing to annotated column which deals with many2many sorting
        #    order_by_column = "notify"
        if query_params['order[0][dir]'] == 'desc':
            order_direction = '-'
        else:
            order_direction = ''
    else:
        order_by_column = default_column
        order_direction = default_direction

    return order_by_column, order_direction
