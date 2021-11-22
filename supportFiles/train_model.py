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
# datasetType 0: CIC-IDS
##
pcapTypeNum = 0
datasetTypeNum = 1

# Select maximum number of files to load
maxNumFiles = 48
filepath = "./dataset/"
zeroVar = []
no_overwrite = False

#---------#
# LOADING #
#---------#
# Needs global variables: zeroVar(if [], its value is set), pcapType, datasetType, datasetTypeNum and filepath
def loadDataset(pcapTypeNum, maxNumFiles):
    global zeroVar, pcapType, datasetType, datasetTypeNum, filepath
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
        full_data.loc[full_data['Label']=='benign','Label']='BENIGN'

    # Print number of flows and attack/bonafide distribution
    if datasetTypeNum == 0:
        columnName = 'Label'
        columnValue = 1
    if datasetTypeNum == 1:
        columnName = 'Label'
        columnValue = 'BENIGN'
       
    #if 'Reconaissansce' in full_data['Label'].unique():
        
    
    examples_bonafide = full_data[full_data[columnName] == columnValue].shape[0]
    total = full_data.shape[0]
    print('Total examples of {0} with {1:0.2f} of attack and {2:0.2f} bonafide packets'.format(total, (total - examples_bonafide)/total, examples_bonafide/total))

    # Print trainDataset informations
    #print(full_data.info())
    #print(full_data.describe())

    # check features with zero variance (not useful for learning) and general ID features
    if zeroVar == []:
        zeroVar = full_data.select_dtypes(exclude='object').columns[(full_data.var() == 0).values]
        zeroVar = np.concatenate((zeroVar.values.T, ['timestamp','flow_ID', 'src_port', 'src_ip', 'dst_ip']))
        #if full_data.columns.isin(zeroVar).any():
        full_data.drop(columns=zeroVar, axis=1, inplace=True)

        featFile = open("./ML-output/zeroVar"+"{0}.txt".format(pcapType[pcapTypeNum]),"w")
        featFile.write("{:}".format(zeroVar))
        featFile.close()
        
    full_data = full_data.fillna(0)
    X = full_data.drop(columns = ["Label"])
    y = full_data.Label
    
    #---------------#
    # DEFINE TARGET #
    #---------------#
    # Define identification scheme
    y[y=='BENIGN'] = 0
    y[y!=0] = 1
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
    global no_overwrite
    # Define ML algorithm, x and y
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

    # Load training set
    X, y = loadDataset(pcapTypeNum, maxNumFiles)

    #----------#
    # TRAINING #
    #----------#
    filename = pcapType[pcapTypeNum] + datasetType[datasetTypeNum].replace(".csv","")
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
        print("Usage: " + sys.argv[0] + " <MAX_NUM_FILES> <DATASET_TYPE> <TRAINING_DATASET> [\"KEEP\"]")
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
        if sys.argv[4] == "KEEP":
            no_overwrite = True
            
        
    runExperiment()
    
#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX