"""Train and compare phishing classifiers on PhiUSIIL using host-level + page-content features.

    python train.py                 # full dataset
    python train.py --sample 40000  # quick run

Outputs (models/, results/):
    models/model_host.joblib   host-features-only model  (used when the page cannot be fetched)
    models/model_full.joblib   host + content features   (used when the page was fetched)
    results/metrics.json       everything the dashboard shows
    results/*.png              plots for the report

Label convention inside this project:  1 = phishing, 0 = legitimate
(the PhiUSIIL CSV uses the opposite: label 1 = legitimate, so we flip it).
"""
from __future__ import annotations

import argparse
import json
import os
import time
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score, recall_score,
                             roc_auc_score, roc_curve)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

from phishguard.content import CONTENT_FEATURES
from phishguard.urlfeatures import HOST_FEATURES, host_features, parse, registered_domain

warnings.filterwarnings("ignore")
SEED = 42
ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data", "PhiUSIIL_Phishing_URL_Dataset.csv")
CACHE = os.path.join(ROOT, "data", "host_features_cache.pkl")
MODELS = os.path.join(ROOT, "models")
RESULTS = os.path.join(ROOT, "results")

# Real-world style legitimate URLs *with paths / without www* - the PhiUSIIL data never contains these.
# Used as a sanity check for the dataset artifact described in the README.
SANITY_LEGIT = [
    "https://github.com/pallets/flask/issues/4500", "https://en.wikipedia.org/wiki/Phishing",
    "https://docs.python.org/3/library/urllib.parse.html", "https://stackoverflow.com/questions/11227809/",
    "https://www.nytimes.com/2024/05/01/world/europe/news.html", "https://mail.google.com/mail/u/0/#inbox",
    "https://learn.microsoft.com/en-us/azure/active-directory/", "https://www.amazon.in/dp/B09G9HD6PD?ref=ppx",
    "https://manipal.edu/mit/department-faculty/department-list/computer-science-engineering.html",
    "https://www.irctc.co.in/nget/train-search", "https://accounts.google.com/signin/v2/identifier",
    "https://scikit-learn.org/stable/modules/ensemble.html", "https://news.ycombinator.com/item?id=39000000",
    "https://www.reddit.com/r/netsec/comments/abc123/", "https://login.microsoftonline.com/common/oauth2/authorize",
    "https://support.apple.com/en-in/HT201994", "https://www.paypal.com/signin", "https://drive.google.com/drive/my-drive",
    "https://docs.github.com/en/get-started", "https://netbanking.hdfcbank.com/netbanking/", "https://www.flipkart.com/search?q=phone",
    "https://web.whatsapp.com/", "https://console.aws.amazon.com/console/home", "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "https://www.bbc.co.uk/news/technology", "https://onlinesbi.sbi/", "https://myaccount.google.com/security",
    "https://outlook.office.com/mail/inbox", "https://www.python.org/downloads/", "https://pypi.org/project/flask/",
]
# Hand-written phishing-style URLs (synthetic, for a recall sanity check only - NOT real feed data)
SANITY_PHISH = [
    "http://secure-login-update-paypal.com", "http://verify-account-bank-login.xyz/signin",
    "https://login-microsoftonline.com.account-verify.top/", "http://amaz0n-support-refund.click/",
    "https://appleid.apple.com.verification-center.info/", "http://sbi-kyc-update.online/login",
    "https://metamask-wallet-connect.web.app/", "https://hdfc-netbanking-secure.ml/", "http://185.234.12.9/paypal/login.php",
    "https://netflix-billing-update.cfd/", "http://facebook-security-check.tk/", "https://paypa1-resolution-center.top/",
]

NEUTRAL_PREFIXES = ["mail", "docs", "blog", "m", "news", "shop", "store", "help", "support", "app", "api", "learn",
                    "en", "careers", "portal", "my", "web", "cloud", "media", "developer", "dev", "community", "press",
                    "download", "services", "online", "secure", "accounts", "login", "id", "auth"]


def group_of(url: str) -> str:
    _, host = parse(url)
    h = host[4:] if host.startswith("www.") else host
    _, sld, suf = registered_domain(h)
    return f"{sld}.{suf}"


def naive_url_features(url: str) -> dict:
    """The *biased* feature set (ablation only): string features incl. www / path / https."""
    sp, host = parse(url)
    return {
        "url_len": len(url), "has_www": int(host.startswith("www.")), "is_https": int(sp.scheme == "https"),
        "has_path": int(len(sp.path) > 1 or bool(sp.query)), "path_len": len(sp.path), "n_slash": url.count("/"),
        "n_dots": url.count("."), "n_digits": sum(c.isdigit() for c in url), "n_hyphen": url.count("-"),
        "n_special": sum(not c.isalnum() for c in url),
    }


def load_features(sample: int | None):
    df = pd.read_csv(DATA, usecols=["URL", "label"] + CONTENT_FEATURES)   # skip big text columns (Title, ...) to save RAM
    df = df.drop_duplicates(subset=["URL"]).reset_index(drop=True)
    df["y"] = 1 - df["label"].astype(int)                      # 1 = phishing
    if sample:
        df = df.sample(sample, random_state=SEED).reset_index(drop=True)
    cache_ok = os.path.exists(CACHE) and not sample
    if cache_ok:
        hf = pd.read_pickle(CACHE)
        if len(hf) != len(df):
            cache_ok = False
    if not cache_ok:
        t = time.time()
        print(f"  extracting host features for {len(df):,} URLs ...", flush=True)
        hf = pd.DataFrame([host_features(u) for u in df["URL"]], columns=HOST_FEATURES)
        if not sample:
            hf.to_pickle(CACHE)
        print(f"  done in {time.time() - t:.0f}s")
    nf = pd.DataFrame([naive_url_features(u) for u in df["URL"]])
    cf = df[CONTENT_FEATURES].astype(float).reset_index(drop=True)
    groups = df["URL"].map(group_of)
    return df, hf, cf, nf, groups



def augment_legit(df_tr: pd.DataFrame, hf_tr: pd.DataFrame, cf_tr: pd.DataFrame, frac: float = 0.35):
    """Break the 'has subdomain => phishing' artifact: in PhiUSIIL only ~6% of legitimate hosts have a subdomain,
    whereas real sites (mail.google.com, docs.python.org, accounts.google.com ...) very often do.
    For a random fraction of *training* legitimate rows we add a copy whose host is prefixed with a common
    functional subdomain. Content features are copied from the original page. Val/test are never augmented."""
    rng = np.random.RandomState(SEED)
    leg = np.where(df_tr["y"].values == 0)[0]
    pick = rng.choice(leg, size=int(len(leg) * frac), replace=False)
    urls = []
    for i in pick:
        _, host = parse(df_tr["URL"].iloc[i])
        base = host[4:] if host.startswith("www.") else host
        pre = NEUTRAL_PREFIXES[rng.randint(len(NEUTRAL_PREFIXES))]
        if rng.rand() < 0.15:
            pre = NEUTRAL_PREFIXES[rng.randint(len(NEUTRAL_PREFIXES))] + "." + pre
        urls.append(f"https://{pre}.{base}/")
    hf_aug = pd.DataFrame([host_features(u) for u in urls], columns=HOST_FEATURES)
    cf_aug = cf_tr.iloc[pick].reset_index(drop=True)
    return hf_aug, cf_aug

def make_models():
    models = {
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, C=1.0)),
        "Linear SVM (calibrated)": make_pipeline(StandardScaler(), CalibratedClassifierCV(LinearSVC(C=0.5, max_iter=5000), cv=3)),
        "Random Forest": RandomForestClassifier(n_estimators=100, min_samples_leaf=5, max_depth=20, n_jobs=-1, random_state=SEED),
    }
    try:
        from xgboost import XGBClassifier
        models["XGBoost"] = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, subsample=0.9,
                                          colsample_bytree=0.9, eval_metric="logloss", random_state=SEED, n_jobs=-1)
    except ImportError:
        models["Gradient Boosting (HistGB)"] = HistGradientBoostingClassifier(max_iter=250, learning_rate=0.1, random_state=SEED)
    return models


def scores(y, p, thr=0.5):
    pred = (p >= thr).astype(int)
    return {"accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred), "recall": recall_score(y, pred),
            "f1": f1_score(y, pred), "roc_auc": roc_auc_score(y, p)}


def run_feature_set(name, X, y, tr, va, te, X_extra=None, y_extra=None):
    print(f"\n=== Feature set: {name}  ({X.shape[1]} features) ===", flush=True)
    table, fitted = {}, {}
    for mname, model in make_models().items():
        t = time.time()
        Xtr, ytr = X.iloc[tr], y.iloc[tr]
        if X_extra is not None:
            Xtr, ytr = pd.concat([Xtr, X_extra], ignore_index=True), pd.concat([ytr, y_extra], ignore_index=True)
        model.fit(Xtr, ytr)
        val = scores(y.iloc[va], model.predict_proba(X.iloc[va])[:, 1])
        tst = scores(y.iloc[te], model.predict_proba(X.iloc[te])[:, 1])
        table[mname] = {"val": val, "test": tst, "train_seconds": round(time.time() - t, 1)}
        fitted[mname] = model
        print(f"  {mname:28s} val F1 {val['f1']:.4f} | test acc {tst['accuracy']:.4f} F1 {tst['f1']:.4f} AUC {tst['roc_auc']:.4f}"
              f"  ({table[mname]['train_seconds']}s)", flush=True)
    best = max(table, key=lambda m: table[m]["val"]["f1"])
    return table, fitted, best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=None)
    args = ap.parse_args()
    os.makedirs(MODELS, exist_ok=True)
    os.makedirs(RESULTS, exist_ok=True)
    if not os.path.exists(DATA):
        raise SystemExit(f"Dataset not found: {DATA}\nPut PhiUSIIL_Phishing_URL_Dataset.csv in data/")

    print("[1/5] Loading data + extracting host features")
    df, hf, cf, nf, groups = load_features(args.sample)
    y = df["y"]
    print(f"  rows={len(df):,}  phishing={int(y.sum()):,}  legitimate={int((1 - y).sum()):,}  unique domains={groups.nunique():,}")

    print("[2/5] Domain-grouped split (70/15/15) - no registered domain appears in two splits")
    gss = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=SEED)
    tr, rest = next(gss.split(hf, y, groups))
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=SEED)
    va_i, te_i = next(gss2.split(hf.iloc[rest], y.iloc[rest], groups.iloc[rest]))
    va, te = rest[va_i], rest[te_i]
    print(f"  train={len(tr):,} val={len(va):,} test={len(te):,}")

    print("[3/5] Training")
    full = pd.concat([hf, cf], axis=1)
    results = {"dataset": {"rows": len(df), "phishing": int(y.sum()), "legitimate": int((1 - y).sum()),
                           "unique_domains": int(groups.nunique()), "sample": args.sample,
                           "split": {"train": len(tr), "val": len(va), "test": len(te)}},
               "feature_sets": {}, "ablation": {}}

    # Ablation 0: the naive URL-string model (shows the dataset artifact)
    naive_table, naive_fit, naive_best = run_feature_set("NAIVE url-string (www/path/https) - ablation only", nf, y, tr, va, te)
    sane = pd.DataFrame([naive_url_features(u) for u in SANITY_LEGIT])
    naive_fp = float((naive_fit[naive_best].predict_proba(sane)[:, 1] >= 0.5).mean())
    sane_p = pd.DataFrame([naive_url_features(u) for u in SANITY_PHISH])
    naive_rec = float((naive_fit[naive_best].predict_proba(sane_p)[:, 1] >= 0.5).mean())
    results["ablation"]["naive_url_string"] = {"features": list(nf.columns), "models": naive_table, "best": naive_best,
                                              "false_positive_rate_on_real_legit_urls": naive_fp,
                                              "recall_on_handwritten_phish_urls": naive_rec}

    meta = {}
    hf_aug, cf_aug = augment_legit(df.iloc[tr], hf.iloc[tr], cf.iloc[tr])
    print(f"  augmentation: +{len(hf_aug):,} legitimate training rows with realistic subdomains")
    results["dataset"]["augmented_legit_rows"] = len(hf_aug)
    for key, X, label, Xa in [("host", hf, "Host / domain / lexical features", hf_aug),
                              ("full", full, "Host + page-content features", pd.concat([hf_aug, cf_aug], axis=1))]:
        ya = pd.Series(np.zeros(len(Xa), dtype=int))
        table, fitted, best = run_feature_set(label, X, y, tr, va, te, Xa, ya)
        model = fitted[best]
        p_te = model.predict_proba(X.iloc[te])[:, 1]
        fpr, tpr, _ = roc_curve(y.iloc[te], p_te)
        step = max(1, len(fpr) // 200)
        cm = confusion_matrix(y.iloc[te], (p_te >= 0.5).astype(int)).tolist()
        print(f"  -> best for '{key}': {best}")
        print("  permutation importance (test subset) ...", flush=True)
        sub = np.random.RandomState(SEED).choice(te, size=min(6000, len(te)), replace=False)
        pi = permutation_importance(model, X.iloc[sub], y.iloc[sub], scoring="f1", n_repeats=3, random_state=SEED, n_jobs=1)
        imp = sorted(zip(X.columns, pi.importances_mean), key=lambda t: -t[1])
        baseline = X.iloc[tr][y.iloc[tr] == 0].median().to_dict()        # "typical legitimate" values for explanations
        sanity_fp, sanity_rec = None, None
        if key == "host":
            sh = pd.DataFrame([host_features(u) for u in SANITY_LEGIT])
            sanity_fp = float((model.predict_proba(sh[X.columns])[:, 1] >= 0.5).mean())
            sp_ = pd.DataFrame([host_features(u) for u in SANITY_PHISH])
            sanity_rec = float((model.predict_proba(sp_[X.columns])[:, 1] >= 0.5).mean())
        joblib.dump({"model": model, "features": list(X.columns), "baseline": baseline, "name": best,
                     "key": key}, os.path.join(MODELS, f"model_{key}.joblib"), compress=3)
        results["feature_sets"][key] = {
            "label": label, "features": list(X.columns), "models": table, "best": best,
            "confusion_matrix": cm, "roc": {"fpr": fpr[::step].round(4).tolist(), "tpr": tpr[::step].round(4).tolist()},
            "importance": [{"feature": f, "importance": round(float(v), 5)} for f, v in imp[:20]],
            "false_positive_rate_on_real_legit_urls": sanity_fp,
            "recall_on_handwritten_phish_urls": sanity_rec,
        }
        meta[key] = (best, table[best]["test"])

    results["sanity_legit_urls"] = SANITY_LEGIT
    results["sanity_phish_urls"] = SANITY_PHISH
    with open(os.path.join(RESULTS, "metrics.json"), "w") as f:
        json.dump(results, f, indent=2)

    print("[4/5] Plots")
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(1, 2, figsize=(12, 4.5))
        for key, c in [("host", "#2b6cb0"), ("full", "#c53030")]:
            r = results["feature_sets"][key]
            ax[0].plot(r["roc"]["fpr"], r["roc"]["tpr"], color=c, label=f"{r['label']} (AUC {meta[key][1]['roc_auc']:.4f})")
        ax[0].plot([0, 1], [0, 1], "k--", lw=.8)
        ax[0].set(xlabel="False positive rate", ylabel="True positive rate", title="ROC (domain-grouped test set)")
        ax[0].legend(loc="lower right", fontsize=8)
        imp = results["feature_sets"]["full"]["importance"][:12][::-1]
        ax[1].barh([i["feature"] for i in imp], [i["importance"] for i in imp], color="#2b6cb0")
        ax[1].set(title="Permutation importance (full model)", xlabel="F1 drop when shuffled")
        plt.tight_layout()
        plt.savefig(os.path.join(RESULTS, "roc_importance.png"), dpi=150)
        plt.close()
    except Exception as exc:  # pragma: no cover
        print("  plot skipped:", exc)

    print("[5/5] Summary (domain-grouped hold-out test set)")
    for key, (best, t) in meta.items():
        print(f"  {key:5s} {best:28s} acc={t['accuracy']:.4f} prec={t['precision']:.4f} rec={t['recall']:.4f} "
              f"f1={t['f1']:.4f} auc={t['roc_auc']:.4f}")
    print(f"  naive URL-string ablation: false-positive rate on {len(SANITY_LEGIT)} real legit URLs = {naive_fp:.0%}")
    h = results["feature_sets"]["host"]
    print(f"  host-feature model:        false-positive rate on same URLs = {h['false_positive_rate_on_real_legit_urls']:.0%}"
          f"; recall on {len(SANITY_PHISH)} hand-written phishing URLs = {h['recall_on_handwritten_phish_urls']:.0%}")


if __name__ == "__main__":
    main()
