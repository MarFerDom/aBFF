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

#--------------------------#
# ZERO VARIANCE READ/WRITE #
#--------------------------#

## Write zero variance feature names into text file: comma separated, no spaces
# Uses global pcapTypeNum value
def zeroVarWrite(ZV,pcapTypeNum):
    featFile = open("./ML-output/zeroVar{0}.txt".format(getDSName(pcapTypeNum)),"w")
    featFile.write(",".join(ZV))
    featFile.close()
    
## Read zero variance feature names from text file: comma separated, no spaces
def zeroVarRead(pcapTypeNum):
    featFile = open("./ML-output/zeroVar{0}.txt".format(getDSName(pcapTypeNum)),"r")
    ZV = featFile.read()
    featFile.close()
    ZV = ZV.split(",")
    return ZV

#---------------------#
# FILE NAMING CONTROL #
#---------------------#

## Get file name from pcap source and feature set type numbers. Used while using fragmented files
def getFilename(pcapTypeNum, datasetTypeNum):
    return pcapType[pcapTypeNum] + datasetType[datasetTypeNum].replace(".csv","")

## Get data set name from pcap source and feature set type numbers
def getDSName(pNum, dNum=1):
    alter = {0:"AB-TRAP" ,1:"NB15" ,2:"CIC-IDS"}
    name = pcapType[pNum]
    if pNum in alter.keys():
        name = alter[pNum]
    return name+datasetType[dNum].replace(".csv","")

#------------------#
# HELPER FUNCTIONS #
#------------------#

## Get pcap number options
def pcapOptions():
    return pcapType.keys()

## Get feature set number options
def featureOptions():
    return datasetType.keys()

## Save LaTex format table of models performance for a given training dataset [update to different tables on same function]
def saveTable(DSName, table):
    featFile = open("./dissertation/{0}_F1table.txt".format(DSName),"w")
    featFile.write("""\\begin{table}[H]\n
                    \t\\centering\n
                    \t\\caption{F1 score of each model in the {0} dataset}\n
                    \t\\label{tab:f1_valid_abtrap}\n
                    \t\t{1}\n
                    \\end{table}""".format(DSName,table.to_latex(index=False, column_format='c'*table.columns.size)))
    featFile.close()
    
## fix for ToN-IoT and BoT-IoT and rogue white spaces
def standardCICFeatureName(features):
    #alvo.columns
    columns = features.to_series().apply(lambda x: x.strip().replace(" ","_").replace("/","_").casefold())
    columns[columns == "flow_id"] = 'flow_ID'
    columns[columns == "label"] = 'Label'
    return columns

#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX


#----------------#
# LOADING MODELS #
#----------------#

# Gets best model and table of best performance per model
##
# modelType: name of file .joblib as given by getFilename(pNum, dNum)
##
def loadModel(modelType):
    files = [s for s in os.listdir("./models/") if ".joblib" in s and modelType in s]
    table = pd.DataFrame({},columns=["model","avg_score","avg_fit_time"])
    bestScore = 0
    for file in files:
        teste = load('./models/'+file)
        indice = np.where(teste.cv_results_["mean_test_score"] == np.amax(teste.cv_results_["mean_test_score"]))[0][0]
        print(indice)
        testline = {"model":file.replace(".joblib","").rsplit("_")[2],
               "avg_score":teste.cv_results_["mean_test_score"][indice],
               "avg_fit_time":teste.cv_results_["mean_fit_time"][indice]}
        if testline["avg_score"] > bestScore:
            bestScore = testline["avg_score"]
            best = teste
        table = table.append(testline, ignore_index = True)
    return (best, table)

    
    
#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX


#-----------------#
# LOADING DATASET #
#-----------------#

def loadDataset(pNum, maxNumFiles, dNum, filepath, BUILD=False):
    finalfilepath = "./dataset/final/{0}.csv".format( getDSName(pNum, dNum) )
    if os.path.isfile(finalfilepath) and not BUILD:
        data = pd.read_csv(finalfilepath, sep=',') 
    else:
        data = buildDataset(pNum, maxNumFiles, dNum, filepath)
    return data


# Needs global variables: datasetTypeNum and filepath
#
## loads data from csv files and format output depending on feature set choice and zero variance variables
###
## pcapTypeNum: pcap option number to find proper dataset
## maxNumFiles: maximum number of files to load, in case of fragmented dataset [update in future to maximum total loaded size]
## datasetTypeNum: Feature set option number to find proper dataset
## filepath: Path to dataset repository from step 2
###

def buildDataset(pcapTypeNum, maxNumFiles, datasetTypeNum, filepath):
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

    
    # fix for ToN-IoT and BoT-IoT name divergence and rogue white spaces [CIC feature set]
    if datasetTypeNum == 1:
        full_data.columns = standardCICFeatureName(full_data.columns)
    
    # Print number of flows and attack/bonafide distribution
    if datasetTypeNum == 0:
        # if NB15 feature set: data['Label'] == 0
        columnName = 'Label'
        columnValue = 0
    if datasetTypeNum == 1:
        # if NB15 feature set: data['Label'] == 'benign'
        columnName = 'Label'
        columnValue = 'benign'        
    examples_bonafide = full_data[full_data[columnName].apply(lambda x: True if x.casefold() == columnValue else False)].shape[0] #examples_bonafide = full_data[full_data[columnName] == columnValue].shape[0]
    total = full_data.shape[0]
    print('Total examples of {0} with {1} attacks and {2} bonafide flows'.format(total, total - examples_bonafide, examples_bonafide))

    # check features with zero variance (not useful for learning) and general ID features
    zeroVar = full_data.select_dtypes(exclude='object').columns[(full_data.var() == 0).values]
    zeroVar = np.concatenate((zeroVar.values.T, ['timestamp','flow_ID', 'src_port', 'src_ip', 'dst_ip']))
    zeroVarWrite(zeroVar,pcapTypeNum)         
    
    full_data = full_data.fillna(0)
    full_data.to_csv("./dataset/final/{0}.csv".format( getDSName(pcapTypeNum, datasetTypeNum) ), index=None, header=True)
       
    return full_data

#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

def setTarget(full_data, pNum, scanOnly, scan, zeroVarType):
    #---------------#
    # DEFINE TARGET #
    #---------------#
    zeroVar = zeroVarRead(zeroVarType)
    full_data.drop(columns=zeroVar, axis=1, inplace=True)
    
    X = full_data.drop(columns = ["Label"])
    y = full_data.Label
    scanTypes = ["reconnaissance", "portscan", "scanning"]
    # Exclude other attacks from data
    if scanOnly and pNum:
        targetText = scanTypes.append("benign")
        temp = full_data["Label"].apply(lambda x: True if x.casefold() in targetText else False)
        X = X[temp]
        y = y[temp]
    # Define identification scheme
    targetText = ["benign"]
    targetToML = (0, 1)
    index = 0
    if scan and pNum:
        targetText = scanTypes
        index = 1
    y = y.apply(lambda x: targetToML[index] if x.casefold() in targetText else targetToML[index-1])
    y = y.astype('int32')
    
    return X, y