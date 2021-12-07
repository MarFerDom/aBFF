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



## returns flow ID string
def flowID(dataframe):
    return dataframe['dst_ip'] + '-' + dataframe['dst_port'].apply(str) + '-' + dataframe['src_ip'] + '-' + dataframe['src_port'].apply(str) + '-' + dataframe['protocol'].apply(str)



## get cic.csv, merge/format labels to CIC-IDS dataset.
def toCIC(labelType, pcapName, filepath):   
    
    print("loading cic.csv..")
    cicfm = pd.read_csv(filepath + "cic.csv", sep=',') # dataset CICFlow Meter
    print("calculating..")
    cicfm['flow_ID'] = flowID(cicfm)
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
    print("labeling...")
    
    # Bonafide.pcap - all benign
    if labelType == 1:
        cicfm['Label'] = 'BENIGN'
        
    # attack.pcap - attack_label.csv (ip, label) #label means 'attack category', not 'attack/benign'
    if labelType == 2:
        labels = pd.read_csv("./labels/attack_label.csv")

        # insert attack category and label
        labels.rename(columns={'ip':'src_ip', 'label':'Label'}, inplace=True)
        labels['Label'] = labels['Label'].str.strip()
        cicfm = cicfm.merge(labels[['srcip','Label']],
                      how='left',
                      left_on=['srcip'],
                      right_on=['srcip'])
    
    # nb15.pcap - NUSW-NB15_GT.csv (Source IP, Destination IP, Source Port, Destination Port, Protocol, Attack category)
    if labelType == 3:
        labels = pd.read_csv("./labels/NUSW-NB15_GT.csv")

        # insert attack category and label
        labels.rename(columns={'Source IP':'src_ip', 'Destination IP':'dst_ip', 'Source Port':'src_port',
                                     'Destination Port':'dst_port', 'Protocol':'protocol', 'Attack category':'Label'}, inplace=True)
        labels = labels.astype({'src_port':'int32','dst_port':'int32','protocol':'string','Label':'string'})
    
    # cic.pcap (Source IP, Source Port, Destination IP, Destination Port, Protocol, Label)
    #if labelType == 4:
        # single label file need to be with the same name as the folder or optional name
        #labels = pd.read_csv("./labels/" + pcapName + ".csv")

        # insert attack category and label
        #labels.rename(columns={'Source IP':'src_ip', 'Destination IP':'dst_ip', 'Source Port':'src_port',
        #                             'Destination Port':'dst_port', 'Protocol':'protocol'}, inplace=True)
    #if labelType in [3, 4]:
        labels['Label'] = labels['Label'].str.strip()
        cicfm = cicfm.merge(labels[['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'Label']],
                      how='left',
                      left_on=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'],
                      right_on=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'])
        
        
    cicfm.fillna(value={'Label': 'BENIGN'}, inplace=True)
    
    #--------------#
    # SAVE DATASET #
    #--------------#
    
    print("saving..")
    cicfm.to_csv("./dataset/" + pcapName + '_CIC.csv', index=None, header=True)
    
if __name__ == "__main__":
    #filepath = "./csv/"
    
    # help
    if len(sys.argv) < 3:
        print("Usage: " + sys.argv[0] + " <TYPE_LABEL> <PATH_TO_CSV> [OUTPUT_NAME]")
        print("Types of labels are \n1 - Bonafide\n2 - Attack\n3 - NB15\n4 - CIC")
        sys.exit()
        
    if len(sys.argv)>2:
        labelType = int(sys.argv[1])
        
        # check for invalid types
        if (labelType > 4) or (labelType < 1):
            print("Types of labels are \n1 - Bonafide\n2 - Attack\n3 - NB15\n4 - CIC")
            sys.exit()
        filepath = sys.argv[2]
        
        # check for missing '/'
        if filepath[len(filepath)-1] != '/':
            filepath += '/'
        pcapName = os.path.basename(os.path.dirname(filepath))
      
    # optional name setting
    if len(sys.argv)>3:
        pcapName = sys.argv[3]
    
    # check for missing files
    if not os.path.isfile(filepath + "cic.csv"):
        print("missing file: ", filepath + "cic.csv")
        sys.exit()
        
    toCIC(labelType, pcapName, filepath)
    print("Done!")