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

from joblib import dump
import myFunc

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


#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

#---------#
# RUNNING #
#---------#
# Runs experiment for all algorithms on chosen dataset and saves as .joblib files
def runExperiment():
    #----------------------#
    # PREPARE FOR TRAINING #
    #----------------------#

    # Load training set
    X, y = myFunc.setTarget(myFunc.loadDataset(pcapTypeNum, maxNumFiles, datasetTypeNum, filepath, []), pcapTypeNum, scanOnly, scan)

    #----------#
    # TRAINING #
    #----------#
    filename = myFunc.getFilename(pcapTypeNum, datasetTypeNum)
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
            
            
        
    runExperiment()
    
#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX