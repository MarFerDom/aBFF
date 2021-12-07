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
from joblib import dump

from sklearn.calibration import CalibratedClassifierCV
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier

from sklearn.preprocessing import StandardScaler#, MinMaxScaler
from sklearn.model_selection import StratifiedKFold, GridSearchCV, cross_val_predict
from sklearn.metrics import accuracy_score, make_scorer, f1_score

import warnings
warnings.filterwarnings('ignore')


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
pcapTypeNum = 0
datasetTypeNum = 1

# Select maximum number of files to load
maxNumFiles = 48
filepath = "./dataset/"
zeroVar = []
no_overwrite = True # skip existing joblib files, dont overwrite
scan = False # target class is Scanning\Reconnaissance
scanOnly = False # remove other attacks from data

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
def loadDataset(pcapTypeNum, maxNumFiles, zeroVarTypeNum):
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

#---------#
# RUNNING #
#---------#
# Runs experiment for testSet
def runExperiment():
    #----------------------#
    # PREPARE FOR TRAINING #
    #----------------------#

    # Load training set
    X, y = loadDataset(pcapTypeNum, maxNumFiles, [])

    #----------#
    # TRAINING #
    #----------#
    filename = getFilename(pcapTypeNum, datasetTypeNum)
    #kf = StratifiedKFold(n_splits=10, shuffle=True, random_state=17) # Train, Test
    gskf = StratifiedKFold(n_splits=10, shuffle=True, random_state=17) # Validation
    perf = f1_score
    #perfROC = roc_auc_score
    prep = StandardScaler() #MinMaxScaler()
    # Normalize input data for training
    prep.fit(X)
    dump(prep, open('models/{0}_prep.pkl'.format(filename), 'wb'))
    #result = {'expected': [], 'predicted': []}
    for algorithm, (clf, parameters) in algorithms.items(): #{'DT': algorithms.get('DT')}.items():
        # file path
        modelPath = "models/{0}_{1}.joblib".format(filename,algorithm)
        # if algorithm already trained and KEEP flag set
        if (os.path.isfile(modelPath)) and no_overwrite:
            print("{0} not overwriten".format(algorithm))
            continue
        #for each ML algorithm: train
        print("training " + algorithm + " from " + filename)
        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # F1 score
        #print("Training for F1 score")
        best = GridSearchCV(clf, parameters, cv=gskf, scoring=make_scorer(perf))
        best.fit(prep.transform(X), y)
        dump(best, modelPath)

    

#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX   
    
    
    
    
    
# IF CALLED FROM TERMINAL

if __name__ == "__main__":

    datasetMSG = "Datasets available are :\n"
    DST_MSG = "Dataset types available are :\n"
    
    # help
    if len(sys.argv) < 4:
        print("Usage: " + sys.argv[0] + " <MAX_NUM_FILES> <DATASET_TYPE> <TRAINING_DATASET> [\"KEEP\"] [\"SCAN_ALL\"] [\"SCAN_ONLY\"]")
        print(datasetMSG, pcapType)
        sys.exit()
        
    if len(sys.argv) > 3:
        pcapTypeNum = int(sys.argv[3])
        datasetTypeNum = int(sys.argv[2])
        maxNumFiles = int(sys.argv[1])
        # check for unknown dataset
        if pcapTypeNum not in pcapType.keys():
            print("Unknown dataset(s): ")
            print(datasetMSG, pcapType)
            sys.exit()
       
        # ToN-IoT and BoT-IoT only available in CIC dataset type
        if pcapTypeNum in [3, 4]:
            datasetTypeNum = 1
            print("ToN-IoT and BoT-IoT only available in CIC dataset type")
        # check for invalid types
        elif (datasetTypeNum not in datasetType.keys()):
            print("Invalid dataset type(s): ")
            print(DST_MSG, datasetType)
            sys.exit()
            
    if len(sys.argv) > 4:
        if "KEEP" in sys.argv[4:]:
            no_overwrite = True
            print("No Overwrite selected. Skipping ML for existing joblib files")
        if "SCAN_ALL" in sys.argv[4:]:
            scan = True # target class is Scanning\Reconnaissance
            print("Target Class: Scanning\\Reconnaissance selected")
        elif "SCAN_ONLY" in sys.argv[4:]:
            scan = True # target class is Scanning\Reconnaissance
            scanOnly = True # exclude non Scanning\Reconnaissance attacks from data
            print("Target Class: Scanning\\Reconnaissance selected, exclude other attacks from Benign data")
            
            
        
    runExperiment()
    
#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX