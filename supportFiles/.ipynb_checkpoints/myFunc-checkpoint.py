#----------------------------------------------------------------------------------------
#
#                                      trainTestCIC.py
#
#
# Input: trainDataset(${PCAP}_CIC.csv) testDataset(${PCAP}_CIC.csv)[list]
# Ouput: (${PCAP}_CIC.csv)
#
# Discription:
# Train with trainDataset and test with testDataset list
#-----------------------------------------------------------------------------------------

import os
import sys
import pandas as pd
import numpy as np
import datetime


# GLOBAL VARIABLES 

pcapType = {0:"output", 1:"NB15_", 2:"WorkingHours", 3:"ToN-IoT", 4:"BoT-IoT"}
datasetType = {0:"_NB15.csv", 1:"_CIC.csv"}

## Select PCAP and dataset types
#
# pcapType 0: MAWILab(no attacks) + synthetic attacks
# pcapType 1: UNSW_NB15
# pcapType 2: CIC-IDS
# pcapType 3: ToN-IoT
# pcapType 4: BoT-IoT
#
# datasetType 0: UNSW_NB15
# datasetType 1: CIC-IDS
##

# Define ML algorithms
algorithms = {
    "MLP" : (MLPClassifier(random_state=17), {
        "hidden_layer_sizes" : (10, 10),
    }),
    "SVM" : (LinearSVC(random_state=17), {}),
    "KNN" : (KNeighborsClassifier(n_jobs=-1), {
        "n_neighbors" : [1, 3, 5]
    }),
    "XGB" : (XGBClassifier(random_state=17, n_jobs=-1), {}),
    "NB" : (GaussianNB(), {}),
    "LR" : (LogisticRegression(random_state=17, n_jobs=-1), {}),
    "RF" : (RandomForestClassifier(random_state=17, n_jobs=-1), {
        "n_estimators" : [10, 15, 20],
        "criterion" : ("gini", "entropy"), 
        "max_depth": [5, 10],
        "class_weight": (None, "balanced", "balanced_subsample")
    }),
    "DT" : (DecisionTreeClassifier(random_state=17), {
        "criterion": ("gini", "entropy"), 
        "max_depth": [5, 10, 15],
        "class_weight": (None, "balanced")
    }),
}


#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

## Write zero variance feature names into text file: comma separated, no spaces
# Uses global pcapTypeNum value
def zeroVarWrite(ZV):
    featFile = open("./ML-output/zeroVar{0}.txt".format(pcapType[pcapTypeNum]),"w")
    featFile.write(",".join(ZV))
    featFile.close()
    
## Read zero variance feature names from text file: comma separated, no spaces
def zeroVarRead(pcapTypeNum):
    featFile = open("./ML-output/zeroVar{0}.txt".format(pcapType[pcapTypeNum]),"r")
    ZV = featFile.read()
    featFile.close()
    ZV = ZV.split(",")
    return ZV

## Get filename from pcap and dataset type numbers
def getFilename(pcapTypeNum, datasetTypeNum):
    return pcapType[pcapTypeNum] + datasetType[datasetTypeNum].replace(".csv","")


#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

#---------#
# LOADING #
#---------#
# Needs global variables: datasetTypeNum and filepath
#
## loads data from csv files and format output depending on feature set choice and zero variance variables
def loadDataset(pcapTypeNum, maxNumFiles, datasetTypeNum, filepath, zeroVarTypeNum):
    full_data = pd.DataFrame({}, columns=[])

    # Load files of pcapType and datasetType no more than maxNumFiles
    files = [s for s in os.listdir(filepath) if (datasetType[datasetTypeNum] in s and pcapType[pcapTypeNum] in s)]
    maxNumFiles = min(maxNumFiles, len(files))
    for file in files[0:maxNumFiles]:
        temp = pd.read_csv(filepath+file, sep=',') 
        full_data = pd.concat([full_data,temp], ignore_index=True)

    # Create AB-TRAP based dataset with all packets (bonafide and attack)
    if pcapTypeNum == 0:
        # Attack dataset
        df_labeled = pd.read_csv(filepath+"attack"+datasetType[datasetTypeNum], sep=',')
        full_data = pd.concat([full_data, df_labeled])
        full_data = full_data.astype({'Label':'str'})
        #full_data.loc[full_data['Label']=='benign','Label']='BENIGN'

    # Format column names for rogue white spaces
    formatedColumns = []
    for x in full_data.columns.values:
        formatedColumns.append(x.strip())
    full_data.columns = formatedColumns
    
    # Print number of flows and attack/bonafide distribution
    if datasetTypeNum == 0:
        columnName = 'Label'
        columnValue = 1
    if datasetTypeNum == 1:
        columnName = 'Label'
        columnValue = 'benign'        
    examples_bonafide = full_data[full_data[columnName].apply(lambda x: True if x.casefold() == columnValue else False)].shape[0]
    #examples_bonafide = full_data[full_data[columnName] == columnValue].shape[0]
    total = full_data.shape[0]
    print('Total examples of {0} with {1} attacks and {2} bonafide flows'.format(total, total - examples_bonafide, examples_bonafide))

    # Print trainDataset informations
    #print(full_data.info())
    #print(full_data.describe())

    # check features with zero variance (not useful for learning) and general ID features
    if zeroVarTypeNum == []:
        zeroVar = full_data.select_dtypes(exclude='object').columns[(full_data.var() == 0).values]
        zeroVar = np.concatenate((zeroVar.values.T, ['timestamp','flow_ID', 'src_port', 'src_ip', 'dst_ip']))
        zeroVarWrite(zeroVar)
    else:
        zeroVar = zeroVarRead(zeroVarTypeNum)
        
    full_data.drop(columns=zeroVar, axis=1, inplace=True)
    full_data = full_data.fillna(0)
    full_data.to_csv("./dataset/final/{0}{1}".format(pcapType[pcapTypeNum], datasetType[datasetTypeNum]), index=None, header=True)
    X = full_data.drop(columns = ["Label"])
    y = full_data.Label
    
    #---------------#
    # DEFINE TARGET #
    #---------------#
    scanTypes = ["reconnaissance", "portscan", "scanning"]
    # Exclude other attacks from data
    if scanOnly:
        temp = X["Label"].apply(lambda x: True if x in targetText else False)
        X = X[temp]
        y = y[temp]
    # Define identification scheme
    targetText = ["benign"]
    targetToML = (0, 1)
    index = 0
    if scan and pcapTypeNum:
        targetText = scanTypes
        index = 1
    y = y.apply(lambda x: targetToML[index] if x.casefold() in targetText else targetToML[index-1])
    y = y.astype('int32')
    
    return X, y

#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX