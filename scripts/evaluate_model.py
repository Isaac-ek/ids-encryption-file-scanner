"""Evaluate the preserved classifier without fitting or overwriting any model artifacts."""
import sys
import json
import hashlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pandas as pd
from xgboost import __version__ as xgboost_version
from sklearn.metrics import classification_report,confusion_matrix,accuracy_score,balanced_accuracy_score
from api.ids_runtime import bundle, artifact_hashes
from api.settings import ROOT,MODEL_ROOT
from scripts.train_xgb_ids import preprocess,col_names

if __name__=='__main__':
    train_path=ROOT/'dataset/NSL_KDD_Train.csv'
    test_path=ROOT/'dataset/NSL_KDD_Test.csv'
    train=pd.read_csv(train_path,names=col_names,header=None)
    test=pd.read_csv(test_path,names=col_names,header=None)
    _,_,values,labels,columns=preprocess(train,test)
    model,scaler,expected_columns=bundle()
    if list(columns)!=list(expected_columns):raise SystemExit('Evaluation feature schema differs from saved bundle; no report written')
    predictions=model.predict(scaler.transform(values))
    report={'model_type':type(model).__name__,'model_sha256':hashlib.sha256((MODEL_ROOT/'ids_model_full.joblib').read_bytes()).hexdigest(),'dataset':'NSL_KDD_Test.csv','dataset_sha256':hashlib.sha256(test_path.read_bytes()).hexdigest(),'records':len(test),'kind':'offline held-out benchmark, not a live-traffic measurement','metrics':{'accuracy':accuracy_score(labels,predictions),'balanced_accuracy':balanced_accuracy_score(labels,predictions),'classification':classification_report(labels,predictions,labels=[0,1,2,3,4],target_names=['Normal','DoS','Probe','R2L','U2R'],output_dict=True,zero_division=0),'confusion_matrix':confusion_matrix(labels,predictions,labels=[0,1,2,3,4]).tolist()}}
    import platform
    from importlib.metadata import version
    report['bundle_sha256']=artifact_hashes()
    report['environment']={'python':platform.python_version(),'platform':platform.system(),'libraries':{name:xgboost_version if name == 'xgboost' else version(name) for name in ['scikit-learn','xgboost','numpy','pandas']}}
    (MODEL_ROOT/'evaluation.json').write_text(json.dumps(report,indent=2))
    print(json.dumps({'model_type':report['model_type'],'records':report['records'],'accuracy':report['metrics']['accuracy'],'macro_f1':report['metrics']['classification']['macro avg']['f1-score']}))
