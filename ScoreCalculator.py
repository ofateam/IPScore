##
# Score calculator
# Includes functions to calculate scores
##

import sys

# Returns system constant values from DB
def get_system_constants(cursor):
    # Create and execute query
    # Instead of querying 5 times, just query once and get results
    system_constants_query = 'SELECT value FROM system_constants'
    cursor.execute(system_constants_query)
    
    # Get query results
    results = cursor.fetchall()
    N = 0
    Ni = int(results[0][0])
    Nu = int(results[1][0])
    Ns = int(results[2][0])
    t = int(results[3][0])
    L = int(results[4][0])
    h = 7 # given by user
    
    # Return system constants
    return N, Ni, Nu, Ns, t, L/100.0, h/1.0


# Static Score Calculation
def calculate_static_score(cursor, K, source_ip, dest_ip, dest_port, service):

    # Define action as default
    action = ''
    
    # Create static score query and execute it
    static_score_query = 'SELECT * FROM policy WHERE srcip = "' + source_ip \
            + '" AND dstip = "' + dest_ip + '" AND port = ' + str(dest_port) \
            + ' AND service = "' + service + '"'

    cursor.execute(static_score_query)
            
    # Check query result
    if cursor.rowcount == 0: # Static rule is not defined
        K = 0
    else:
        # Check action field
        action = cursor.fetchall()[0][5]
        if action == 'allow':
            K = 1
        else:
            K = 0

    return K


# Source Score Calculation
def calculate_source_score(cursor, S, service, dest_port, datetime, Ni, Nu, L):
    # Pre-check : find service type
    service_type_query = 'SELECT type FROM services WHERE service = "' \
        + service + '" AND port = ' + str(dest_port)
    cursor.execute(service_type_query)
            
    # If this service+port does not exists in services table
    # Assume that they are external services and set N value
    if cursor.rowcount == 0:
        srv_type = 'e'
        N = Nu
    else:
        srv_type = str(cursor.fetchall()[0][0])
        if srv_type == 'i':
            N = Ni
        elif srv_type == 'e':
            N = Nu
        else:
            print 'Unknown service type!'
            sys.exit()

    # Find tns value
    tns_query = 'SELECT  COUNT(DISTINCT srcip) FROM runtime_tmp WHERE service =  "' \
        + service + '" AND port = ' + str(dest_port) + ' AND datetime >= "' \
        + datetime + '" - INTERVAL 10 MINUTE  AND datetime <= "' + datetime + '"'

    cursor.execute(tns_query)

    # Set tns value
    if cursor.rowcount == 0:
        tns = 0.0
    else:
        tns = float(cursor.fetchall()[0][0])

    # Calculate source score
    if tns < N:
        S = 1.0 - (1.0-L)*(tns/N)
    else:
        S = L + 1.0 - (tns/N)

    return S


# Familiarity Score Calculation
def calculate_familiarity_score(cursor, service, F, out_log_id, date, source_ip, dest_port, h, L):
    # Firstly, get log id of the current log from traffic table
    familiarity_score_query = 'SELECT log_id FROM traffic WHERE srcip = "' \
        + source_ip + '" AND port = ' + str(dest_port) + ' AND service = "' + service + '"'
    cursor.execute(familiarity_score_query)
        
    if cursor.rowcount == 0: # this is a new log
        n_days = 0
    else:
        # Get log id
        out_log_id = int(cursor.fetchall()[0][0])
        #print 'outlog = ', out_log_id
        
        # Secondly, search log id in previous days of training data
        # by avoiding from current date
        n_days_query = 'SELECT * FROM log WHERE log_id = ' \
            + str(out_log_id) + ' AND date != "' + str(date) + '"'
        cursor.execute(n_days_query)

        # Set number of days
        n_days = cursor.rowcount

        # Thirdly, calculate the familiarity score
        if n_days > 0:
            F = L + (1.0-L)*(n_days/h)
        else:
            F = 0

    return out_log_id, F


# Calculate traffic score
def calculate_traffic_score(cursor, database, T, service, dest_port, datetime, out_log_id, t):
    # Find n_cur
    n_cur_query = 'SELECT  COUNT(srcip) FROM runtime_tmp WHERE service =  "' \
        + service + '" AND port = ' + str(dest_port) + ' AND datetime >= "' \
        + datetime + '" - INTERVAL 10 MINUTE  AND datetime <= "' + datetime + '"'
    cursor.execute(n_cur_query)
    n_cur = int(cursor.fetchall()[0][0])
                    
    # Find n_avg
    if out_log_id < 0:
        n_avg = 0.0
        n_max = 0.0
    else:
        # Find n_avg
        n_avg_query = 'CALL get_navg('+ str(out_log_id) +');'
        cursor = get_new_cursor(cursor, database)
        cursor.execute(n_avg_query)
        n_avg = cursor.fetchall()[0][0]
        
        # Find n_max
        n_max_query = 'CALL get_nmax('+ str(out_log_id) +');'
        cursor = get_new_cursor(cursor, database)
        cursor.execute(n_max_query)
        n_max = cursor.fetchall()[0][0]

    # Set T value
    if n_cur > n_max + (n_max * t/100.0): # Set tolerance
        T = 0.0
    elif n_cur > n_avg:
        T = (n_max - n_cur)/(n_max-n_avg)
    else:
        T = 1.0

    return T


# Calculate variation score
def calculate_variation_score(cursor, V, tnd, source_ip, dest_port, datetime, Ns, L):
    # Find tnd value
    tnd_query = 'SELECT  COUNT(DISTINCT dstip, port, service) FROM runtime_tmp WHERE srcip =  "' \
        + source_ip + '" AND datetime >= "' \
        + datetime + '" - INTERVAL 10 MINUTE  AND datetime <= "' + datetime + '"' 

                    
    cursor.execute(tnd_query)
                    
    # Set tnd value
    if cursor.rowcount == 0:
        tnd = 0.0
    else:
        tnd = float(cursor.fetchall()[0][0])

    # Calculate variation score
    if tnd < Ns:
        V = 1.0 - ((1.0-L)*(tnd/Ns))
    else:
        V = L + 1.0 - (tnd/Ns)

    return V


# Get new cursor to avoid conflict among queries
def get_new_cursor(cursor, database):
    cursor.close()
    return database.cursor()

