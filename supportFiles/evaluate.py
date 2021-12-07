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

import myFunc
from joblib import load

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




#---------#
# RUNNING #
#---------#
# Runs experiment for testSet
def runEvaluation():
    #--------------------#
    # LOAD BEST ML MODEL #
    #--------------------#
    DSName = getDSNem(pNum)
    best, table = loadModel(modelType)
    saveTable(DSName, table)

    # Load training set
    X, y = myFunc.loadDataset(pcapTypeNum, maxNumFiles, datasetTypeNum, filepath, [], scan, scanOnly)

    #---------#
    # TESTING #
    #---------#
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