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
import seaborn as sns
import matplotlib.pyplot as plt

from sklearn.tree import DecisionTreeClassifier
#from sklearn.naive_bayes import GaussianNB
#from sklearn.linear_model import LogisticRegression
#from sklearn.neural_network import MLPClassifier
#from sklearn.ensemble import RandomForestClassifier

from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler#, MinMaxScaler
from sklearn.model_selection import StratifiedKFold, GridSearchCV, cross_val_predict
from sklearn.metrics import accuracy_score, make_scorer, f1_score, roc_auc_score, roc_curve

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
       
    if 'Reconaissansce' in full_data['Label'].unique():
        
    
    examples_bonafide = full_data[full_data[columnName] == columnValue].shape[0]
    total = full_data.shape[0]
    print('Total examples of {0} with {1:0.2f} of attack and {2:0.2f} bonafide packets'.format(total, (total - examples_bonafide)/total, examples_bonafide/total))

    # Print trainDataset informations
    print(full_data.info())
    print(full_data.describe())

    # check features with zero variance (not useful for learning) and general ID features
    if zeroVar == []
        zeroVar = full_data.select_dtypes(exclude='object').columns[(full_data.var() == 0).values]
        zeroVar = np.concatenate((zeroVar.values.T, ['timestamp','flow_ID', 'src_port', 'src_ip', 'dst_ip']))
        #if full_data.columns.isin(zeroVar).any():
        full_data.drop(columns=zeroVar, axis=1, inplace=True)
        high_corr = full_data.corr().abs().round(2)
        high_corr_var = high_corr[high_corr>0.5]
        plt.figure(figsize = (20,16))
        sns.heatmap(high_corr_var, xticklabels=high_corr_var.columns, yticklabels=high_corr_var.columns, annot=True);
        # Save HeatMap as .png
        plt.savefig(pcapType[pcapTypeNum]+fileLabel+'heatmap.png')
        
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
def runExperiment(**kwargs):
    #----------------------#
    # PREPARE FOR TRAINING #
    #----------------------#
    # Define ML algorithm, x and y
    algorithms = {
        #"MLP" : (MLPClassifier(), {
        #    "hidden_layer_sizes" : (10, 10),
        #}),
        #"XGB" : (XGBClassifier(), {}),
        "NB" : (GaussianNB(), {}),
        "LR" : (LogisticRegression(), {}),
        "RF" : (RandomForestClassifier(random_state=17, n_jobs=-1), {
            "n_estimators" : [10, 50, 100, 200],
            "criterion" : ("gini", "entropy"), 
            "max_depth": [5, 10],
            "class_weight": (None, "balanced", "balanced_subsample")
        }),
        "DT" : (DecisionTreeClassifier(), {
            "criterion": ("gini", "entropy"), 
            "max_depth": [x for x in range(1,21)],
            "class_weight": (None, "balanced")
        }),
    }

    # Load training set
    X, y = loadDataset(pcapTypeNum, maxNumFiles)

    #----------#
    # TRAINING #
    #----------#
    kf = StratifiedKFold(n_splits=10, shuffle=True, random_state=17) # Train, Test
    gskf = StratifiedKFold(n_splits=5, shuffle=True, random_state=17) # Validation
    perf = f1_score
    perfROC = roc_auc_score
    prep = StandardScaler() #MinMaxScaler()
    # Normalize input data for training
    prep.fit(X)
    
    result = {'expected': [], 'predicted': []}
    for algorithm, (clf, parameters) in {'DT': algorithms.get('DT')}.items(): #algorithms.items():
        # file path
        filename = 'ML-output/' + algorithm + "_" + pcapType[pcapTypeNum] + datasetType[datasetTypeNum]
        
        #for each ML algorithm: train
        print("training " + algorithm + " from " + pcapType[pcapTypeNum] + datasetType[datasetTypeNum])

        # F1 score
        print("Training for F1 score")
        best = GridSearchCV(clf, parameters, cv=gskf, scoring=make_scorer(perf))
        best.fit(prep.transform(X), y)
        
        # save graph of F1 score per max depth
        print("Drawing graph for best F1 score")
        gini = {}
        entropia = {}
        for i in range(0,len(best.cv_results_['params'])):
            # print(best.cv_results_['params'][i], best.cv_results_['mean_test_score'][i], best.cv_results_['std_test_score'][i])
            if best.cv_results_['params'][i]['criterion'] == "gini":
                gini.update({best.cv_results_['params'][i]['max_depth']: best.cv_results_['mean_test_score'][i]})
            else:
                entropia.update({best.cv_results_['params'][i]['max_depth']: best.cv_results_['mean_test_score'][i]})
        lists1 = sorted(gini.items())
        lists2 = sorted(entropia.items())
        x_gini, y_gini = zip(*lists1)
        x_entropia, y_entropia = zip(*lists2)
        #plt.figure(figsize=(10,8))
        #plt.rcParams.update({'font.size': 15})
        #plt.title('Performance according to grid-search parameters')
        plt.ylabel('F1-score', fontsize=20)
        plt.xlabel('Max depth', fontsize=20)
        plt.plot(x_gini, y_gini, '--', label='Gini')
        plt.plot(x_entropia, y_entropia, '.-', label='Entropy')
        plt.legend(loc="lower right");
        plt.savefig(filename+"f_curve.png", dpi=300, bbox_inches = "tight")
        
        # ROC
        print("Training for best AUC")
        bestROC = GridSearchCV(clf, parameters, cv=gskf, scoring=make_scorer(perfROC))
        bestROC.fit(prep.transform(X), y)
        
            # check the following code!!           

        print("Training for F1 score")
        clf = DecisionTreeClassifier(criterion=bestROC.best_params_['criterion'],
                                     max_depth=bestROC.best_params_['max_depth'],
                                     class_weight=bestROC.best_params_['class_weight'])

        predicted = cross_val_predict(clf, X, y, cv=kf, method='predict_proba')
        print(predicted.transpose()[1]) # Probability of the positive class

        fpr, tpr, thr = roc_curve(y, predicted.transpose()[1])
            
        plt.figure()
        lw = 2
        plt.plot(fpr, tpr, color='darkorange',lw=lw)
        plt.plot([0, 1], [0, 1], color='navy', lw=lw, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver operating characteristic example')
        plt.legend(loc="lower right")
        plt.show()
        plt.savefig(filename+'ROC_curve.pdf'), dpi=600, bbox_inches = "tight")

        Fscores = cross_val_score(clf, X, y, cv=kf, scoring='f1') # recall
        print("F1-Score: %0.3f (+/- %0.2f)" % (Fscores.mean(), Fscores.std() * 2))

        clf.fit(X, y) # qual a diferença entre isso e usar o predict_proba do GridSearchCV após fit?
        feature_importance = np.array(clf.feature_importances_)
        feature_names = np.array(X.columns)
        data = {'feature_name': feature_names, 'feature_importance': feature_importance}

        fi_df = pd.DataFrame(data)
        fi_df.sort_values(by=['feature_importance'], ascending=False, inplace=True)
        relevantes = fi_df[fi_df.feature_importance > 0]

        #plt.figure(figsize=(10,8))
        g=sns.barplot(x=relevantes['feature_importance'], y=relevantes['feature_name'])
        plt.xlabel('Importance', fontsize=20)
        plt.ylabel('Feature', fontsize=20);
        i=0
        for index, row in relevantes.iterrows():
            g.text(row.feature_importance+0.03, i, round(row.feature_importance, 4), color='black', ha="center", va="center", fontsize=9)
            i+=1
        plt.savefig(filename+'feature_importance.pdf'), dpi=600, bbox_inches = "tight")
        #
        
        
        for test in kwargs['testSet']:
            # files are named after the algorithm, training dataset, testing dataset and their feature group
            filename = filename + "_" + pcapType[test]
            xtest, ytest = loadDataset(test, maxNumFiles)
            print("Testing with: ", pcapType[test])

            # F1 score
            score = perf(best.predict(prep.transform(xtest)), ytest)

            # ROC
            result['expected'] = ytest
            result['predicted'] = bestROC.predict_proba(prep.transform(xtest)).transpose()[1]
            
            
            #-------------------------------------#
            # DO SOMETHING WITH THE SCORE/RESULTS # XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            #-------------------------------------#
            
            # Calculate, plot and save ROC
            plt.style.use('plot_style.txt')
            plt.figure()
            
            fpr, tpr, thresholds = roc_curve(result['expected'], result['predicted'])
            AUC = auc(fpr, tpr)

            plt.plot(fpr, tpr, label="{} (AUC={:.4f})".format(model_key, AUC))
            
            # save ROC data
            pd.DataFrame.from_dict(data={ 'fpr': fpr, 'tpr': tpr, 'thresholds': thresholds }).to_csv(filename + 'ROC_data.csv', index=False)

            # save ROC graph
            plt.plot([0,1], [0,1], color='gray', linestyle='--')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            #plt.title('Receiver operating characteristic (ROC)')
            plt.legend(loc="lower right")
            plt.savefig(filename + 'ROC.png', dpi=300, bbox_inches="tight")
       

    

#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX   
    
    
    
    
    
# IF CALLED FROM TERMINAL

if __name__ == "__main__":
    
    global pcapTypeNum, datasetTypeNum, maxNumFiles

    datasetMSG = "Datasets available are :\n"
    DST_MSG = "Dataset types available are :\n"
    
    # help
    if len(sys.argv) < 5:
        print("Usage: " + sys.argv[0] + " <MAX_NUM_FILES> <DATASET_TYPE> <TRAINING_DATASET> <TESTING_DATASET_1> [<TESTING_DATASET_2>.. <TESTING_DATASET_N>]")
        print(datasetMSG+pcapType)
        sys.exit()
        
    if len(sys.argv) > 4:
        
        # check for unknown dataset
        if ([x for x in sys.argv[3:] if x not in pcapType.keys()] != []):
            print("Unknown dataset(s): ")
            print(datasetMSG+pcapType)
            sys.exit()
        pcapTypeNum = sys.argv[3]
        testSet = sys.argv[4:]
        
        # ToN-IoT and BoT-IoT only available in CIC dataset type
        if pcapTypeNum in [3, 4]:
            datasetTypeNum = 1
            print("ToN-IoT and BoT-IoT only available in CIC dataset type")
        # check for invalid types
        elif (sys.argv[2] not in datasetType.keys()):
            print("Invalid dataset type(s): ")
            print(DST_MSG+datasetType)
            sys.exit()
        else:
            datasetTypeNum = sys.argv[2]
        
    runExperiment('testSet'=testSet)
    
#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX