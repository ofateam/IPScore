##
## IPScore : Intrusion Prevention System Based on
## Statistical Access Pattern Analyses
## For CS577 Class Project, Spring 2017
## Coder OFA, @Bilkent University
##


# Built-in Libraries
import os, sys
import MySQLdb
from time import time
from datetime import datetime, timedelta


# Other Python Files
import LogParser
import ScoreCalculator


# Database Parameters
HOST = '127.0.0.1'
USER = 'root'
PASSWORD = '123'
DB_NAME = 'ips'


# Function : log_parser
# Goal : read input log file line by line and
# add necessary information into training DB
# by parsing them
def get_ipscore(log_file_name):
    
    # Database Connection
    database = MySQLdb.connect(HOST, USER, PASSWORD, DB_NAME)
    cursor = database.cursor()
    
    # Get system constants from DB
    N, Ni, Nu, Ns, t, L, h = ScoreCalculator.get_system_constants(cursor)


    # Open test log file and read line by line
    with open(log_file_name, "r") as log_file:
        for line in log_file:
            # Define all score values
            K = 0 # static score
            S = 0 # source score
            F = 0 # familiarity score
            T = 0 # traffic score
            V = 0 # variation score
            P = 0 # overall score
    
            tns = 0 # tns value
            tnd = 0 # tnd value
            n_days = 0 # number of days value
            out_log_id = -1 # log id
            
            
            ##
            ## 1 ## Read current log and get attributes
            ##
            # Check line attributes and size
            attributes = line.split(',')
            size = len(attributes)
            if size == LogParser.LINE_SIZE and attributes[8].strip() \
                    and '=,' not in line and '=""' not in line:
                # Get attributes of the current log
                date_time, date, time = LogParser.get_datetime(attributes)
                source_ip = LogParser.get_source(attributes)
                dest_ip, dest_port = LogParser.get_destination(attributes)
                action, service = LogParser.get_action_service(attributes)
                        
                # Parse time of the current log
                current_time = str(date_time.time()).split(':')
                hour = current_time[0].strip()
                minute = current_time[1].strip()
                second = current_time[2].strip()
                time_interval = hour + minute[0] + '0'
                        
                # Set time interval of the current log
                if int(minute[0]) == 5:
                    if int(hour) == 23:
                        time_interval += '_' + hour + str(59)
                    elif int(hour) < 9:
                        time_interval += '_0' + str(int(hour) + 1) + '00'
                    elif int(hour) >= 9:
                        time_interval += '_' + str(int(hour) + 1) + '00'
                else:
                    time_interval += '_' + hour + str(int(minute[0]) + 1) + '0'
                        
                #print date_time, source_ip, dest_ip, dest_port, action, service


                ##
                ## 2 ## Check time of current log and decide to calculate score
                ## If the log is in the first 10 minutes, insert it into
                ##      runtime_tmp table and training data
                ## Else, calculate a score for current log and do other insertions
                ##

                
                # Define default run time table values
                dec_action = 'booting'
                score = -1
                debug = 'booting'
                
                
                # Check time of current log to know whether it is in the first 10 min
                if time_interval != '0000_0010':
                    # Calculate static score
                    K = ScoreCalculator.calculate_static_score(cursor, K, source_ip, dest_ip, dest_port, service)

                    # Calculate source score
                    S = ScoreCalculator.calculate_source_score(cursor, S, service, dest_port, (str(date) + ' ' + str(time)), Ni, Nu, L)
                
                    # Calculate familiarity score
                    out_log_id, F = ScoreCalculator.calculate_familiarity_score(cursor, service, F, out_log_id, date, source_ip, dest_port, h, L)
                    
                    # Calculate traffic score
                    T = ScoreCalculator.calculate_traffic_score(cursor, database, T, service, dest_port, (str(date) + ' ' + str(time)), out_log_id, t)
                    
                    # Calculate variation score
                    V = ScoreCalculator.calculate_variation_score(cursor, V, tnd, source_ip, dest_port, (str(date) + ' ' + str(time)), Ns, L)
                 
                 
                    # Calculate overall score and set decision, score and debug values
                    P = K + (S+F+T+V)/4.0
                    if P > L/100.0:
                        dec_action = 'allow'
                    else:
                        dec_action = 'deny'
                    score = P
                    debug = str(K) + ';' + str(S) + ';' + str(F) + ';' + str(T) + ';' + str(V)
                    
                    
                ##
                ## 3 ## Insert current log into runtime_tmp table
                ##
                insert_tmp_query = insert_query = 'INSERT INTO runtime_tmp (datetime, srcip, dstip, port, service, action, score, debug) \
                    VALUES("' + (str(date) +' ' + str(time)) + '","' + source_ip + '","' + dest_ip + '",' + str(dest_port) \
                        + ',"' + service + '","' + dec_action + '",' + str(score) + ',"' + debug + '")'
                cursor.execute(insert_tmp_query)

                ##
                ## 4 ## Insert current log into training tables in DB
                ##
                # Insert current traffic into database
                log_id = LogParser.insert_traffic_into_db(cursor, source_ip, dest_ip, dest_port, service)
            
                # Increase count of the current log
                LogParser.update_log_count(cursor, log_id, date, time_interval)


    # Close database connection
    database.close()


# Main Function
if __name__ == '__main__':
    print "\n# IPScore #\n"
    print "Input file : ", sys.argv[1]
    
    # Call log parser to process input data
    get_ipscore(log_file_name = sys.argv[1])

