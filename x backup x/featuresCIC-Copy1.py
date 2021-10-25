#----------------------------------------------------------------------------------------
#
#                                      featuresCIC.py
#
#
# Input: CICFlowMeter(cic.csv), Labels()
# Ouput: (${PCAP}_CIC.csv)
#
# Discription:
# Extract 84 features as in ( et al 2017) from ${PCAP}.pcap file
#-----------------------------------------------------------------------------------------


# DATASET INFO AND PCAP FILE SOURCES

## CIC-IDS
### source: https://www.unb.ca/cic/datasets/ids-2017.html

import os
import sys
import pandas as pd
import warnings
warnings.filterwarnings('ignore')

    
## get argus.csv, conn.log, http.log and ftp.log, merge/format to NB15 dataset and calculate 12 additional featues
def main(pcap, filepath):   
    
    print("loading cic.csv..")
    cicfm = pd.read_csv(filepath + "cic.csv", sep=',') # dataset CICFlow Meter
    print("calculating..")
    cicfm['flow_ID'] = cicfm['dst_ip'] + '-' + cicfm['dst_port'].apply(str) + '-' + cicfm['src_ip'] +
                            '-' + cicfm['src_port'].apply(str) + '-' + cicfm['protocol'].apply(str)
    #cicfm = cicfm.merge(labels[['srcip','dstip','sport','dport','attack_cat']], how='left',
    #         left_on=['src_ip','dst_ip','src_port','dst_port'],
    #         right_on=['srcip','dstip','sport','dport'])
    #cicfm.fillna(value={'attack_cat': 'benign'}, inplace=True)
    #cicfm.drop(['srcip','dstip','sport','dport'], axis = 1, inplace = True)
   

    #--------#
    # LABELS #
    #--------#
    # src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'
    # loading Labels
    
    # Bonafide.pcap - all benign
    if labelType == 1:
        DS['Label'] = ['BENIGN']
        
    # attack.pcap - attack_label.csv (ip, label) #label means 'attack category', not 'attack/benign'
    if labelType == 2:
        labels = pd.read_csv("./labels/attack_label.csv")

        # insert attack category and label
        labels.rename(columns={'ip':'src_ip', 'label':'Label'}, inplace=True)
        labels['attack_cat'] = labels['attack_cat'].str.strip()
        DS = DS.merge(labels[['srcip','attack_cat']],
                      how='left',
                      left_on=['srcip'],
                      right_on=['srcip'])
    
    # nb15.pcap - NUSW-NB15_GT.csv (Source IP, Destination IP, Source Port, Destination Port, Protocol, Attack category)
    if labelType == 3:
        labels = pd.read_csv("./labels/NUSW-NB15_GT.csv")

        # insert attack category and label
        labels.rename(columns={'Source IP':'src_ip', 'Destination IP':'dst_ip', 'Source Port':'src_port',
                                     'Destination Port':'dst_port', 'Protocol':'protocol', 'Attack category':'Label'}, inplace=True)
    
    # cic.pcap (Source IP, Source Port, Destination IP, Destination Port, Protocol, Label)
    if labelType == 4:
        # single label file need to be with the same name as the folder or optional name
        labels = pd.read_csv("./labels/" + pcap + ".csv")

        # insert attack category and label
         labels.rename(columns={'Source IP':'src_ip', 'Destination IP':'dst_ip', 'Source Port':'src_port',
                                     'Destination Port':'dst_port', 'Protocol':'protocol'}, inplace=True)
    if labelType in [3, 4]:
        labels['attack_cat'] = labels['attack_cat'].str.strip()
        DS = DS.merge(labels[['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'Label']],
                      how='left',
                      left_on=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'],
                      right_on=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'])
        
        
    DS.fillna(value={'attack_cat': ''}, inplace=True)
    DS['Label'] = 1
    DS.loc[DS['attack_cat'] == '','Label'] = 0
    
    #--------------#
    # SAVE DATASET #
    #--------------#
    
    print("saving..")
    cicfm.to_csv("./dataset/" + pcapName + '_CIC.csv', index=None, header=True)
    
if __name__ == "__main__":
    filepath = "./csv/"
    if len(sys.argv) == 0:
        print("Usage: featuresCIC.py <PATH_TO_CSV> [OUTPUT_NAME]")
        sys.exit()
    if len(sys.argv)>1:
        filepath = sys.argv[1]
        if filepath[len(filepath)-1] != '/':
            filepath += '/'
        pcapName = os.path.basename(os.path.dirname(filepath))
    if len(sys.argv)>2:
        pcapName = sys.argv[2]
    main(pcapName, filepath)