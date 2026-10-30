# Dataset Directory

This directory stores the dataset and cached features used for model training.

## PhiUSIIL Phishing URL Dataset

The model training pipeline in `train.py` expects the dataset file:
`PhiUSIIL_Phishing_URL_Dataset.csv`

### Source & Download
You can download the dataset from either:
- **UCI Machine Learning Repository**: [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)
- **Kaggle**: [PhiUSIIL Phishing URL Dataset](https://www.kaggle.com/datasets/waelalsafwani/phiusiil-phishing-url-dataset)

Place the extracted `PhiUSIIL_Phishing_URL_Dataset.csv` directly into this `data/` folder.

### Pre-trained Models
You do **not** need to download the dataset or retrain the models to use PhishGuard! Pre-trained weights (`model_host.joblib` and `model_full.joblib`) are already committed under `models/`, allowing you to run `python api.py` immediately.
