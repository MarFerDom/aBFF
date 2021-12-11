#----------------------------------------------------------------------------------------
#
#                                      evaluate.py
#
#
# Input: models(${PCAP}_${FEATURE_SET}_${ML}_.joblib) testDataset(${PCAP}_${FEATURE_SET}.csv)[list]
# Ouput: a line for performance table in (fscore_${PCAP}_${FEATURE_SET}.csv)
#
# Discription:
# Test trained models with testDataset list
#-----------------------------------------------------------------------------------------

################## TO DO: ################################
# 1 - verify NB-15 code for string identification NB15_  #
# 2 - make target list part of command line atttribute   #
# 3 - improve myFunc.loadModel() function                #
##########################################################

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

TARGET_LIST = [2, 3, 4]

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
def runEvaluation(pNum, maxNumFiles, dNum=1, scanOnly=False, scan=True, no_overwrite=True):

    #--------------------#
    # LOAD BEST ML MODEL #
    #--------------------#
    
    DSName = myFunc.getDSName(pNum, dNum, scanOnly, scan)    # get data set name
    scorefile = "./dissertation/fscore_{0}.csv".format(DSName) # from data set's name get model and f1-score file's path
    best, prep, table, algo = myFunc.loadModel(DSName)
    myFunc.saveTable( table, '{0}_F1table'.format(DSName),
                     'F1 score of each model in the {0} dataset'.format(DSName),
                     'f1_valid_{0}'.format(DSName.casefold()) )                         # Update model performance table for tested data set
    
    # make target list for testing model
    targetList = TARGET_LIST
    if os.path.isfile(scorefile) and no_overwrite:          # if file already exists, load table
        print("Found F1-score file for {0} data set".format(DSName))
        table = pd.read_csv(scorefile, sep=',')
        if table["ML"] != algo:
            print("Best algorithm changed! Retest: {:}".format(table.columns.to_list()) )
    else:                                                   # if file doesnt exist, make table
        print("F1-score file for {0} data set not found. Creating..".format(DSName))
        table = pd.DataFrame(index=[DSName])
        table["ML"] = algo
    # remove targets already tested or out of bound
    targetList = [x for x in targetList if (x in myFunc.pcapOptions() and myFunc.getDSName(x, dNum) not in table.columns)]
     
    #---------#
    # TESTING #
    #---------#
    
    MSG = "Evaluating {0}\'s {1} ML model on ".format(DSName, algo) + "{0} data set"
    
    for targetNum in targetList:                            # test model on every target in the list
        # load target data set
        tName = myFunc.getDSName(targetNum, dNum)
        X, y = myFunc.setTarget(myFunc.loadDataset(targetNum, maxNumFiles, dNum), targetNum, scanOnly, scan, pNum)
        print(MSG.format(tName))
        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # calculate f1-score for this target data set
        # print('DEBUG :', X)
        table[tName] = best.score(prep.transform(X),y)
        print("F1-score: {0}".format(table[tName]))
        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    table.to_csv(scorefile, index=None, header=True) # save F1-score table file
    
    
#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX 
    
    
    
# IF CALLED FROM TERMINAL

if __name__ == "__main__":

    datasetMSG = "Datasets available are :\n"
    DST_MSG = "Dataset types available are :\n"
    
    scanOnly = False
    scan = False
    no_overwrite = False
    
    # help
    if len(sys.argv) < 4:
        print("Usage: " + sys.argv[0] + " <MAX_NUM_FILES> <FEATURE_SET> <PCAP_SOURCE> [\"KEEP\"] [\"SCAN_ALL\"] [\"SCAN_ONLY\"]")
        print(datasetMSG, pcapType)
        sys.exit()
        
    if len(sys.argv) > 3:
        pNum = int(sys.argv[3])
        dNum = int(sys.argv[2])
        maxNumFiles = int(sys.argv[1])
        # check for unknown dataset
        if pNum not in myFunc.pcapOptions():
            print("Unknown dataset(s): ")
            print(datasetMSG, myFunc.pcapType)
            sys.exit()
       
        # ToN-IoT and BoT-IoT only available in CIC dataset type
        if pNum in [3, 4]:
            dNum = 1
            print("ToN-IoT and BoT-IoT only available in CIC dataset type")
        # check for invalid types
        elif (dNum not in myFunc.featureOptions()):
            print("Invalid dataset type(s): ")
            print(DST_MSG, myFunc.datasetType)
            sys.exit()
            
    if len(sys.argv) > 4:
        if "KEEP" in sys.argv[4:]:
            no_overwrite = True
            print("No Overwrite selected. Skipping data sets already tested")
        if "SCAN_ALL" in sys.argv[4:]:
            scan = True # target class is Scanning\Reconnaissance
            print("Target Class: Scanning\\Reconnaissance selected")
        elif "SCAN_ONLY" in sys.argv[4:]:
            scan = True # target class is Scanning\Reconnaissance
            scanOnly = True # exclude non Scanning\Reconnaissance attacks from data
            print("Target Class: Scanning\\Reconnaissance selected, exclude other attacks from Benign data")
                  
        
    runEvaluation(pNum, maxNumFiles, dNum, scanOnly, scan, no_overwrite)
    
#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX