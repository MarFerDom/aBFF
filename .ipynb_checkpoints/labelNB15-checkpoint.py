#----------------------------------------------------------------------------------------
#
#                                      NB15_dataset.py
#
#
# Input: Argus(argus.csv), Zeek(conn.log, http.log, ftp.log), Labels(attack_label.csv)
# Ouput: (${PCAP}_NB15.csv)
#
# Discription:
# Extract 49 features as in (Moustafa et al 2015) from ${PCAP}.pcap file
#-----------------------------------------------------------------------------------------


# DATASET INFO AND PCAP FILE SOURCES

## UNSW-NB15
### source: https://research.unsw.edu.au/projects/unsw-nb15-dataset

import os
import sys
import pandas as pd
import numpy as np
import warnings
warnings.filterwarnings('ignore')
import socket
from datetime import datetime


#df = pd.DataFrame(np.empty((0, 49)))     # 49 empty columns
DS = []
 
    

## convert to int
def portsAsInt(x):
    if isinstance(x,str):     #if is string
        if x.isnumeric():        #and if contains only decimals
            return int (x)
        else:
            try:
                return int(float(x))
            except ValueError:
                return int(x,16) #if contains hex number
    return 0

    
## get argus.csv, conn.log, http.log and ftp.log, merge/format to NB15 dataset and calculate 12 additional featues
def main(pcap, filepath):   
    
    global DS
    
    # load the CSVs from a specific pcap file
    HAS_CONN = os.path.isfile(filepath+"conn.log")
    HAS_HTTP = os.path.isfile(filepath+"http.log")
    HAS_FTP = os.path.isfile(filepath+"ftp.log")

    print("loading argus.csv..")
    df = pd.read_csv(filepath+"argus.csv")                                             # dataset Argus
    print("argus.csv", df.shape)

    if(HAS_CONN):
        print("loading conn.log..")
        zconn = pd.read_csv(filepath+"conn.log", sep='\t', skiprows = [0, 1, 2, 3, 4, 5, 7]) # dataset Zeek Conn
        zconn.columns = np.concatenate([zconn.columns[1:], ['drop']])                 # mark extra column for drop
        zconn.drop('drop', axis = 1, inplace = True)                                  # drop marked column
        print("conn.log", zconn.shape)
    else:
        print("no argus.csv")

    if(HAS_HTTP):
        print("loading http.log..")
        zhttp = pd.read_csv(filepath+"http.log", sep='\t', skiprows = [0, 1, 2, 3, 4, 5, 7]) # dataset Zeek http
        zhttp.columns = np.concatenate([zhttp.columns[1:], ['drop']])                 # mark extra column for drop
        zhttp.drop('drop', axis = 1, inplace = True)                                  # drop marked column
        print("http.log", zhttp.shape)
    else:
        print("no http.log")
    # trans_depth and response_body_len

    if(HAS_FTP):
        print("loading ftp.log..")
        zftp = pd.read_csv(filepath+"ftp.log", sep='\t', skiprows = [0, 1, 2, 3, 4, 5, 7])   # dataset Zeek ftp
        zftp.columns = np.concatenate([zftp.columns[1:], ['drop']])                   # mark extra column for drop
        zftp.drop('drop', axis = 1, inplace = True)                                   # drop marked column
        print("ftp.log", zftp.shape)
    else:
        print("no ftp.log")

        
        
    #-------#
    # ARGUS #
    #-------#
    
    #Format argus.csv: data fix port and time parsing, uses portsAsInt(x)
    df = df.astype({'SrcAddr':'string', 'Sport':'string', 'DstAddr':'string', 'Dport':'string', 'Proto':'string', 'State':'string'})
    df['Dport'] = df['Dport'].apply(lambda x: portsAsInt(x))
    df['Sport'] = df['Sport'].apply(lambda x: portsAsInt(x))
    df[['Sport','Dport']].fillna(0, inplace=True)

    if (df['Dport'].notna().all() and df['Sport'].notna().all()):
        if (df['Dport'].apply(lambda x: isinstance(x,int)).all() and df['Sport'].apply(lambda x: isinstance(x,int)).all()):
            print("all ports are properly parsed")
        else:
            print("not all port properly parsed")
    else:
        print("some ports are NA")

    df = df.astype({'SrcAddr':'string', 'Sport':'int32', 'DstAddr':'string', 'Dport':'int32', 'Proto':'int32', 'State':'string'})
    if isinstance(df['StartTime'][0],str):
        df['StartTime'] = df['StartTime'].apply(lambda x: float(x))
        df['LastTime'] = df['LastTime'].apply(lambda x: float(x))
   


    #----------#
    # CONN.LOG #
    #----------#

   
    if HAS_CONN:
        #Format conn.log data
        if zconn.columns.isin(['id.orig_h','id.orig_p','id.resp_h','id.resp_p']).any():
            badIndex = zconn[['id.orig_p','id.resp_p']].isna().all(axis=1)
            badIndex = badIndex[badIndex].index
            zconn.drop(badIndex, axis=0, inplace=True)
            zconn = zconn.astype({'id.orig_h':'string', 'id.orig_p':'int32', 'id.resp_h':'string', 'id.resp_p':'int32', 'proto':'string','service':'string'})

        zconn.columns = ['StartTime', 'uid', 'SrcAddr', 'Sport', 'DstAddr','Dport','Proto', 'service', 'duration', 'orig_bytes', 'resp_bytes','conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history','orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes','tunnel_parents']
        # may be removed -- adapt argus protocol display for compatibility instead
        test = zconn['Proto']
        for loc in test.index:
            if not(str(test.iloc[loc]).isnumeric()):
                if test.iloc[loc] == "tcp":
                    zconn['Proto'].iloc[loc] = '6'
                if test.iloc[loc] == "udp":
                    zconn['Proto'].iloc[loc] = '17'
                if test.iloc[loc] == "ipv4":
                    zconn['Proto'].iloc[loc] = '4'
                if test.iloc[loc] == "icmp":
                    zconn['Proto'].iloc[loc] = '1'
                if test.iloc[loc] == "igmp":
                    zconn['Proto'].iloc[loc] = '2'
        zconn = zconn.astype({'Proto':'int32'})
        zconn['StartTime'] = zconn['StartTime'].apply(lambda x: float(x))
        print("Unique protocol list :", zconn['Proto'].unique())
        
        # Merging data from conn.log
        DS = df.merge(zconn[['SrcAddr','Sport','DstAddr','Dport', 'Proto','StartTime','service','duration','conn_state']], 
                      how='left',
                      left_on=['SrcAddr', 'Sport','DstAddr','Dport','Proto','StartTime'],
                      right_on=['SrcAddr', 'Sport', 'DstAddr', 'Dport','Proto','StartTime'])
        DS.fillna(value={'service': '-','duration': 0,'conn_state': '-'}, inplace=True)
    else:
        print("No conn.log")
        DS = df
        DS[['service','duration','conn_state']] = ['-',0,'-']
 
    

    #----------#
    # HTTP.LOG #
    #----------#
    
    
    if HAS_HTTP:
        # Formating http.log
        if zhttp.columns.isin(['ts','id.orig_h','id.orig_p','id.resp_h','id.resp_p']).any():
            zhttp.columns = ['StartTime', 'uid', 'SrcAddr', 'Sport', 'DstAddr','Dport','trans_depth', 'method', 'host', 'uri', 'referrer','version',
                             'user_agent','origin', 'request_body_len', 'response_body_len','status_code', 'status_msg', 'info_code', 'info_msg','tags',
                             'username', 'password', 'proxied', 'orig_fuids', 'orig_filenames','orig_mime_types', 'resp_fuids', 'resp_filenames', 
                             'resp_mime_types']
        badIndex = zhttp[['Sport','Dport']].isna().all(axis=1)
        badIndex = badIndex[badIndex].index
        zhttp.drop(badIndex, axis=0, inplace=True)
        zhttp['service'] = 'http'
        zhttp['Proto'] = 6
        zhttp = zhttp.astype({'StartTime':'float','SrcAddr':'string', 'Sport':'int32','DstAddr':'string','Dport':'int32','Proto':'int32','service':'string',
                              'trans_depth':'int32','response_body_len':'int32','method':'string'})
         # Merging data from http.log (port 80)
        DS = DS.merge(zhttp[['SrcAddr','Sport','DstAddr','Dport','Proto','service','trans_depth','response_body_len','method']],
                       how='left',
                       left_on=['SrcAddr', 'Sport', 'DstAddr', 'Dport','Proto','service'],
                       right_on=['SrcAddr', 'Sport', 'DstAddr', 'Dport','Proto','service'])
        print("Flows: ", DS.shape[0], "\nFlows not in http.log: ", DS.shape[0] -
              DS.merge(zhttp[['SrcAddr','Sport','DstAddr','Dport','Proto','service','trans_depth','response_body_len','method']],
                       how='inner',
                       left_on=['SrcAddr', 'Sport','DstAddr', 'Dport','Proto','service'],
                       right_on=['SrcAddr', 'Sport', 'DstAddr', 'Dport','Proto','service']).shape[0])
        print("HTTP Flows in DS: ", DS[DS['service']=='http'].shape[0])
        DS.fillna(value={'trans_depth': 0,'response_body_len': 0,'method': '-'}, inplace=True)
    else:
        print("No http.log")
        DS[['trans_depth','response_body_len','method']] = [0,0,'-'] 
    
    
   
    #---------#
    # FTP.LOG #
    #---------#
    
    if HAS_FTP: 
        # Formating ftp.log data
        if zftp.columns.isin(['id.orig_h','id.orig_p','id.resp_h','id.resp_p']).any():
            zftp.columns = ['StartTime', 'uid', 'SrcAddr', 'Sport', 'DstAddr','Dport','user','password','command','arg','mime_type','file_size','reply_code',
                            'reply_msg','data_channel.passive','data_channel.orig_h','data_channel.resp_h','data_channel.resp_p','fuid']
        badIndex = zftp[['Sport','Dport']].isna().all(axis=1)
        badIndex = badIndex[badIndex].index
        zftp.drop(badIndex, axis=0, inplace=True)
        zftp['service'] = 'ftp'
        zftp['Proto'] = 6
        zftp = zftp.astype({'StartTime':'float','SrcAddr':'string', 'Sport':'int32', 'DstAddr':'string','Dport':'int32',
                            'Proto':'int32','service':'string','user':'string','password':'string', 'command':'string'})
        
        # Merging data from ftp.log (port 21)
        DS = DS.merge(zftp[['SrcAddr','Sport','DstAddr','Dport','Proto','service','user','password','command']],
                        how='left',
                        left_on=['SrcAddr', 'Sport', 'DstAddr', 'Dport','Proto','service'],
                        right_on=['SrcAddr', 'Sport', 'DstAddr', 'Dport','Proto','service'])
        print("Flows in DS: ", DS.shape[0], "\nFlows in ftp.log: ", zftp.shape[0],)
        print("Non repeated in zftp", zftp[zftp.duplicated(subset=['SrcAddr', 'Sport', 'DstAddr', 'Dport','Proto','service'], keep='first')].shape[0])
        DS.fillna(value={'user': '-','password': '-','command': '-'}, inplace=True)
        DS[DS['service']=='ftp'].head(5)
    else:
        print("No ftp.log")
        DS[['user','password','command']] = ['-','-','-']    
    
    

    #-------------------------------#
    # Fitting into UNSW-NB15 format #
    #-------------------------------#
    DS = DS[['SrcAddr', 'Sport', 'DstAddr', 'Dport', 'Proto', 'State', 'Dur','SrcBytes', 'DstBytes', 'sTtl', 'dTtl',
               'SrcLoss', 'DstLoss','service', 'SrcLoad', 'DstLoad', 'SrcPkts', 'DstPkts', 'SrcWin', 'DstWin', 'SrcTCPBase',
               'DstTCPBase', 'sMeanPktSz', 'dMeanPktSz', 'trans_depth','response_body_len', 'SrcJitter', 'DstJitter','StartTime',
               'LastTime', 'SIntPkt', 'DIntPkt', 'TcpRtt', 'SynAck', 'AckDat', 'Trans', 'Min',
               'Max', 'Sum', 'duration', 'conn_state', 'method', 'user', 'password', 'command']]
    DS.columns = ['srcip', 'sport', 'dstip', 'dport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl',
                   'sloss', 'dloss', 'service', 'sload', 'dload', 'spkts', 'dpkts', 'swin', 'dwin', 'stcpb',
                   'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'sjit', 'djit', 'stime',
                   'ltime', 'sintpkt', 'dintpkt', 'tcprtt', 'synack', 'ackdat', 'Trans', 'Min',
                   'Max', 'Sum', 'duration', 'conn_state', 'method', 'user', 'password', 'command']

    #--------------------------#
    # General Purpose Features #
    #--------------------------#

    print("calculating General Purpose Features..")
    #'is_sm_ips_ports'
    DS['is_sm_ips_ports'] = DS['srcip'] == DS['dstip']
    DS['is_sm_ips_ports'].replace(to_replace={True: 1, False: 0}, inplace=True)
    # DS.fillna(value={'is_sm_ips_ports': 0}, inplace=True)

    # 'ct_state_ttl'
    test = DS.groupby(['state','sttl','dttl'], as_index=False).size()
    for line in test.index:
        DS.loc[ (DS['state'] == test.iloc[line,0]) & (DS['sttl'] == test.iloc[line,1]) & (DS['dttl'] == test.iloc[line,2]),
               'ct_state_ttl'] = test.iloc[line,3]

    DS.fillna(value={'ct_state_ttl': 0}, inplace=True)
    DS['ct_state_ttl'] = DS['ct_state_ttl'].apply(int)
    #DS['ct_state_ttl']

    # 'ct_flw_http_mthd' 
    test = DS.groupby(['method'], as_index=False).size()
    test.loc[ test['method'] == '-', 'size'] = 0
    for line in test.index:
        DS.loc[ DS['method'] == test.iloc[line,0] , 'ct_flw_http_mthd'] = test.iloc[line,1]

    DS.fillna(value={'ct_flw_http_mthd': 0}, inplace=True)
    DS['ct_flw_http_mthd'] = DS['ct_flw_http_mthd'].apply(int)
    DS['ct_flw_http_mthd'].unique()

    # is_ftp_login
    DS['is_ftp_login'] = '-'
    DS.loc[ (DS['user'] == '-') | (DS['user'] == '<unknown>') | (DS['user'] == 'anonymous') | (DS['password'] == '-'), 'is_ftp_login'] = 0
    DS.loc[ (DS['is_ftp_login'] != 0) & (DS['service'] == 'ftp'), 'is_ftp_login'] = 1
    DS[(DS['is_ftp_login'] == 1)]

    # ct_ftp_cmd
    test = DS[DS['service']=='ftp'].groupby(['srcip','dstip','sport','dport','command'], as_index=False).size()
    test.drop(index=test[test['command']=='-'].index, inplace=True)
    test = test.groupby(['srcip','dstip','sport','dport'], as_index=False).size()
    test['service'] = 'ftp'
    test.rename(columns={"size":"ct_ftp_cmd"}, inplace=True)
    if not(DS.columns.str.contains('ct_ftp_cmd', regex=False).any()):
        DS = DS.merge(test, how='left', left_on=['srcip','dstip','sport','dport','service'],
                                    right_on=['srcip','dstip','sport','dport','service'])
        DS.fillna(value={'ct_ftp_cmd': 0}, inplace=True)
        DS['ct_ftp_cmd'] = DS['ct_ftp_cmd'].apply(int)
    test.columns

    #---------------------#
    # Connection Features #
    #---------------------#
    
    print("calculating Connection Features..")
    DS.sort_values('ltime', inplace=True, kind='mergesort', ignore_index=True)

    for indice in range(len(DS.index)):
        if indice == 0:
            DS[['ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm']] = np.zeros(7,dtype=int)
            continue
        temp = min(101,indice)
        priors = DS.iloc[range(indice-temp,indice)]

        # ct_srv_src
        test = priors.groupby(['srcip','service'], as_index=False).size()
        test = test[(test[['srcip','service']] == DS[['srcip','service']].iloc[indice]).all(axis=1)]['size']
        if not test.empty:
            DS.at[indice,'ct_srv_src'] = test.iloc[0]

        # ct_srv_dst
        test = priors.groupby(['dstip','service'], as_index=False).size()
        test = test[(test[['dstip','service']] == DS[['dstip','service']].iloc[indice]).all(axis=1)]['size']
        if not test.empty:
            DS.at[indice,'ct_srv_dst'] = test.iloc[0]

        # ct_dst_ltm 
        test = priors.groupby(['dstip'], as_index=False).size()
        test = test[(test['dstip'] == DS['dstip'].iloc[indice])]['size']
        if not test.empty:
            DS.at[indice,'ct_dst_ltm'] = test.iloc[0]

        # ct_src_ltm
        test = priors.groupby(['srcip'], as_index=False).size()
        test = test[(test['srcip'] == DS['srcip'].iloc[indice])]['size']
        if not test.empty:
            DS.at[indice,'ct_src_ltm'] = test.iloc[0]

        # ct_src_dport_ltm
        test = priors.groupby(['srcip','dport'], as_index=False).size()
        test = test[(test[['srcip','dport']] == DS[['srcip','dport']].iloc[indice]).all(axis=1)]['size']
        if not test.empty:
            DS.at[indice,'ct_src_dport_ltm'] = test.iloc[0]

        # ct_dst_sport_ltm
        test = priors.groupby(['dstip','sport'], as_index=False).size()
        test = test[(test[['dstip','sport']] == DS[['dstip','sport']].iloc[indice]).all(axis=1)]['size']
        if not test.empty:
            DS.at[indice,'ct_dst_sport_ltm'] = test.iloc[0]

        # ct_dst_src_ltm
        test = priors.groupby(['srcip','dstip'], as_index=False).size()
        test = test[(test[['srcip','dstip']] == DS[['srcip','dstip']].iloc[indice]).all(axis=1)]['size']
        if not test.empty:
            DS.at[indice,'ct_dst_src_ltm'] = test.iloc[0]
   
    #--------------#
    # SAVE DATASET #
    #--------------#
    
    print("saving..")
    DS.fillna(value={'sttl': 0, 'dttl': 0, 'swin': 0, 'dwin': 0, 'stcpb': 0, 'dtcpb': 0, 'sjit': 0, 'djit': 0,'dintpkt': 0}, inplace=True)
    if DS.columns.isin(['Trans', 'Min', 'Max', 'Sum', 'duration', 'conn_state', 'method', 'user', 'password', 'command']).any():
        DS.drop(['Trans', 'Min', 'Max', 'Sum', 'duration', 'conn_state', 'method', 'user', 'password', 'command'], axis = 1, inplace = True)
    DS.to_csv(filepath + pcapName + '_NB15.csv', index=None, header=True)

    
if __name__ == "__main__":
    filepath = "./"
    if len(sys.argv) == 0:
        print("Usage: featuresNB15.py <PATH_TO_CSV> [OUTPUT_NAME]")
        sys.exit()
    if len(sys.argv)>1:
        filepath = sys.argv[1]
        if filepath[len(filepath)-1] != '/':
            filepath += '/'
        pcapName = os.path.basename(os.path.dirname(filepath))
    if len(sys.argv)>2:
        pcapName = sys.argv[2]
    main(pcapName, filepath)