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

# verify NB-15 code for string identification NB15_

import os
import sys
import pandas as pd
import numpy as np
import datetime
from joblib import dump
import myFunc

from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier

from sklearn.calibration import CalibratedClassifierCV
from sklearn.preprocessing import StandardScaler#, MinMaxScaler
from sklearn.model_selection import StratifiedKFold, GridSearchCV, cross_val_predict
from sklearn.metrics import accuracy_score, make_scorer, f1_score

import warnings
warnings.filterwarnings('ignore')


# GLOBAL VARIABLES 

## Select PCAP and dataset types
#
# pcapType 0: AB-TRAP - MAWILab(no attacks) + synthetic attacks
# pcapType 1: UNSW_NB15
# pcapType 2: CIC-IDS
# pcapType 3: ToN-IoT
# pcapType 4: BoT-IoT
#
# datasetType 0: UNSW_NB15
# datasetType 0: CIC-IDS
##


#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX


# only working with CIC features for now !!!

#---------#
# RUNNING #
#---------#

# Runs experiment for testSet
def runEvaluation(pNum, maxNumFiles, dNum, scanOnly, scan, no_overwrite=True):

    #--------------------#
    # LOAD BEST ML MODEL #
    #--------------------#
    
    DSName = myFunc.getDSNem(pNum, dNum, scanOnly, scan)
    # from data set's name get model and f1-score file's path
    scorefile = "./ML-output/fscore_{0}.csv".format(DSName)
    best, prep, table = myFunc.loadModel(DSName)
    # Update model performance table for tested data set
    myFunc.saveTable(DSName, table)

    # make target list for testing model
    targetList = [2, 3, 4]
    if os.path.isfile(scorefile) and no_overwrite:
        # if file already exists, load table
        print("Found F1-score file for {0} data set".format(DSName))
        table = pd.read_csv(scorefile, sep=',')
    else:
        # if file doesnt exist, make table
        print("F1-score file for {0} data set not found. Creating..".format(DSName))
        table = pd.DataFrame()
        table.index = [DSName]
    # remove targets already tested or out of bound
    targetList = [x for x in targetList and x in myFunc.pcapOptions() and myFunc.getDSName(x, dNum) not in table.columns]
     
    #---------#
    # TESTING #
    #---------#
    
    ## TO DO: #########################
    # how to to get model name?       #
    # how to test with best model?    #
    ###################################
    
    # test model on every target in the list
    perf = f1_score
    for targetNum in targetList:
        # load target data set
        tName = myFunc.getDSName(targetNum, dNum)
        X, y = myFunc.setTarget(myFunc.loadDataset(targetNum, maxNumFiles, dNum), targetNum, scanOnly, scan, pNum)
        print("Evaluating {0}\'s {1} ML model on {2} data set".format(DSName, best.model, tName)) # not real attribute
        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # calculate f1-score for this target data set
        table[tName] = best.dontknow(prep.transform(X),y, perf) # not real function
        print("F1-score: {0}".format(table[tName]))
        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # save F1-score table file
    table.to_csv( scorefile ), index=None, header=True)
    
    
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
        if pcapTypeNum not in myFunc.pcapOptions():
            print("Unknown dataset(s): ")
            print(datasetMSG, pcapType)
            sys.exit()
       
        # ToN-IoT and BoT-IoT only available in CIC dataset type
        if pcapTypeNum in [3, 4]:
            datasetTypeNum = 1
            print("ToN-IoT and BoT-IoT only available in CIC dataset type")
        # check for invalid types
        elif (datasetTypeNum not in myFunc.featureOptions()):
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
                  
        
    runEvaluation(pNum, maxNumFiles, dNum, scanOnly, scan, no_overwrite)
    
#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX