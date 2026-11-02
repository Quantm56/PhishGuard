"""Train the deployed host classifier with domain-grouped evaluation.

Page security evidence is applied by predictor.py as explicit rules. Layout
counts are deliberately excluded from learned verdicts: the retired full model
learned unreliable collection shortcuts. No site-specific scores are assigned.
Train/validation/test domains remain disjoint; only training data is augmented.
Outputs: models/model_host.joblib and current host-model metrics/plots.
"""
from __future__ import annotations

import argparse
import json
import os
import time
import warnings

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score, roc_curve, auc)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

from phishguard.urlfeatures import HOST_FEATURES, host_features, parse, registered_domain

warnings.filterwarnings("ignore")
SEED = 42
ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data", "PhiUSIIL_Phishing_URL_Dataset.csv")
CACHE = os.path.join(ROOT, "data", "host_features_cache.pkl")
MODELS = os.path.join(ROOT, "models")
RESULTS = os.path.join(ROOT, "results")

# Real-world legitimate URLs representing diverse web architectures (SPAs, deep links, auth portals, docs)
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
    "https://chatgpt.com/", "https://grok.com/", "https://www.artificialintelligence-news.com/#"
]

SANITY_PHISH = [
    "http://secure-login-update-paypal.com", "http://verify-account-bank-login.xyz/signin",
    "https://login-microsoftonline.com.account-verify.top/", "http://amaz0n-support-refund.click/",
    "https://appleid.apple.com.verification-center.info/", "http://sbi-kyc-update.online/login",
    "https://metamask-wallet-connect.web.app/", "https://hdfc-netbanking-secure.ml/", "http://185.234.12.9/paypal/login.php",
    "https://netflix-billing-update.cfd/", "http://facebook-security-check.tk/", "https://paypa1-resolution-center.top/",
]

NEUTRAL_PREFIXES = [
    "mail", "docs", "blog", "m", "news", "shop", "store", "help", "support", "app", "api", "learn",
    "en", "careers", "portal", "my", "web", "cloud", "media", "developer", "dev", "community", "press",
    "download", "services", "online", "secure", "accounts", "login", "id", "auth",
    "netbanking", "onlinebanking", "banking", "corporate", "workspace", "identity",
    "dashboard", "customer", "business", "selfservice", "ebanking", "connect",
    "modern-app", "user-portal", "cloud-console", "web-app", "app-dev", "auth-service",
    "my-account", "single-sign-on", "corp-net", "internal-tools", "customer-care",
    "dev-portal", "secure-auth", "api-gateway", "identity-provider", "account-management",
]


def group_of(url: str) -> str:
    _, host = parse(url)
    h = host[4:] if host.startswith("www.") else host
    _, sld, suf = registered_domain(h)
    return f"{sld}.{suf}" if suf else sld


def load_features(sample: int | None):
    # Load dataset with refined content features
    df = pd.read_csv(DATA, usecols=["URL", "label"])
    df = df.drop_duplicates(subset=["URL"]).reset_index(drop=True)
    df["y"] = 1 - df["label"].astype(int)  # 1 = phishing, 0 = legitimate
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

    groups = df["URL"].map(group_of)
    return df, hf, groups


def augment_legit_data(df_tr: pd.DataFrame, hf_tr: pd.DataFrame):
    """Training-only subdomain diversity; never assign labels to user-supplied sites."""
    rng = np.random.RandomState(SEED)
    legit = np.where(df_tr["y"].values == 0)[0]
    pick = rng.choice(legit, size=int(len(legit) * 0.40), replace=False)
    urls = []
    for i in pick:
        _, host = parse(df_tr["URL"].iloc[i])
        base = host[4:] if host.startswith("www.") else host
        prefix = NEUTRAL_PREFIXES[rng.randint(len(NEUTRAL_PREFIXES))]
        if rng.rand() < 0.15:
            prefix = NEUTRAL_PREFIXES[rng.randint(len(NEUTRAL_PREFIXES))] + "." + prefix
        urls.append(f"https://{prefix}.{base}/")
    return pd.DataFrame([host_features(url) for url in urls], columns=HOST_FEATURES)


def make_models():
    models = {
        "HistGradientBoosting": HistGradientBoostingClassifier(max_iter=250, learning_rate=0.08, min_samples_leaf=20, random_state=SEED),
        "Random Forest": RandomForestClassifier(n_estimators=120, min_samples_leaf=4, max_depth=22, n_jobs=-1, random_state=SEED),
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2500, C=1.0)),
        "Linear SVM (calibrated)": make_pipeline(StandardScaler(), CalibratedClassifierCV(LinearSVC(C=0.5, max_iter=5000), cv=3)),
    }
    return models


def evaluate_predictions(y_true, y_prob, threshold=0.5):
    y_pred = (y_prob >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    prec, rec, _ = precision_recall_curve(y_true, y_prob)
    pr_auc = float(auc(rec, prec))

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
        "pr_auc": pr_auc,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "confusion_matrix": cm.tolist()
    }


def run_feature_set(name, X, y, tr, va, te, X_extra=None, y_extra=None):
    print(f"\n=== Training: {name} ({X.shape[1]} features) ===", flush=True)
    table, fitted = {}, {}
    for mname, model in make_models().items():
        t0 = time.time()
        Xtr, ytr = X.iloc[tr], y.iloc[tr]
        if X_extra is not None:
            Xtr = pd.concat([Xtr, X_extra], ignore_index=True)
            ytr = pd.concat([ytr, y_extra], ignore_index=True)
        model.fit(Xtr, ytr)
        dur = round(time.time() - t0, 1)

        p_val = model.predict_proba(X.iloc[va])[:, 1]
        p_te = model.predict_proba(X.iloc[te])[:, 1]
        val_m = evaluate_predictions(y.iloc[va], p_val)
        te_m = evaluate_predictions(y.iloc[te], p_te)

        table[mname] = {"val": val_m, "test": te_m, "train_seconds": dur}
        fitted[mname] = model
        print(f"  {mname:25s} | val F1: {val_m['f1']:.4f} | test Acc: {te_m['accuracy']:.4f} F1: {te_m['f1']:.4f} AUC: {te_m['roc_auc']:.4f} FPR: {te_m['false_positive_rate']:.4f} ({dur}s)", flush=True)

    best = max(table, key=lambda m: table[m]["val"]["f1"])
    return table, fitted, best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=None)
    args = ap.parse_args()
    os.makedirs(MODELS, exist_ok=True)
    os.makedirs(RESULTS, exist_ok=True)

    log_path = os.path.join(RESULTS, "train_log.txt")
    log_file = open(log_path, "w", encoding="utf-8")

    def log(msg=""):
        print(msg, flush=True)
        log_file.write(str(msg) + "\n")
        log_file.flush()

    log("[1/5] Loading PhiUSIIL dataset and extracting features")
    df, hf, groups = load_features(args.sample)
    y = df["y"]
    log(f"  Rows: {len(df):,} | Phishing: {int(y.sum()):,} | Legitimate: {int((1-y).sum()):,} | Unique Registered Domains: {groups.nunique():,}")

    log("[2/5] Strict domain-grouped split (70/15/15) - unseen domains in val and test")
    gss = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=SEED)
    tr, rest = next(gss.split(hf, y, groups))
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=SEED)
    va_i, te_i = next(gss2.split(hf.iloc[rest], y.iloc[rest], groups.iloc[rest]))
    va, te = rest[va_i], rest[te_i]
    log(f"  Train: {len(tr):,} | Val: {len(va):,} | Test: {len(te):,}")

    hf_aug = augment_legit_data(df.iloc[tr], hf.iloc[tr])
    y_aug = pd.Series(np.zeros(len(hf_aug), dtype=int))
    log(f"  Augmentation (Train only): +{len(hf_aug):,} legitimate subdomain variants")


    results = {
        "dataset": {
            "rows": len(df),
            "phishing": int(y.sum()),
            "legitimate": int((1 - y).sum()),
            "unique_domains": int(groups.nunique()),
            "sample": args.sample,
            "split": {"train": len(tr), "val": len(va), "test": len(te)},
            "augmented_legit_rows": len(hf_aug),
        },
        "feature_sets": {},
    }

    meta = {}
    feature_runs = [("host", hf, "Host / domain / lexical features (30 features)", hf_aug)]
    results["deployment"] = {"active_model": "host", "content_policy": "Explicit security evidence rules; layout features excluded", "legacy_full_deployed": False}
    for key, X, label, Xa in feature_runs:
        table, fitted, best = run_feature_set(label, X, y, tr, va, te, Xa, y_aug)
        model = fitted[best]
        p_te = model.predict_proba(X.iloc[te])[:, 1]
        fpr, tpr, _ = roc_curve(y.iloc[te], p_te)
        step = max(1, len(fpr) // 200)

        # Baseline median vector for occlusion explanation
        baseline = X.iloc[tr][y.iloc[tr] == 0].median().to_dict()

        # Permutation feature importance on a random representative test sample
        sub = np.random.RandomState(SEED).choice(te, size=min(6000, len(te)), replace=False)
        pi = permutation_importance(model, X.iloc[sub], y.iloc[sub], scoring="f1", n_repeats=3, random_state=SEED, n_jobs=-1)
        imp = sorted(zip(X.columns, pi.importances_mean), key=lambda t: -t[1])

        # Evaluate on real-world sanity sets
        sanity_fp, sanity_rec = None, None
        if key == "host":
            sh = pd.DataFrame([host_features(u) for u in SANITY_LEGIT])
            sanity_fp = float((model.predict_proba(sh[X.columns])[:, 1] >= 0.5).mean())
            sp_ = pd.DataFrame([host_features(u) for u in SANITY_PHISH])
            sanity_rec = float((model.predict_proba(sp_[X.columns])[:, 1] >= 0.5).mean())

        joblib.dump({
            "model": model,
            "features": list(X.columns),
            "baseline": baseline,
            "name": best,
            "key": key,
            "version": "3.0-host-security-evidence"
        }, os.path.join(MODELS, f"model_{key}.joblib"), compress=3)

        results["feature_sets"][key] = {
            "label": label,
            "features": list(X.columns),
            "models": table,
            "best": best,
            "test_metrics": table[best]["test"],
            "roc": {"fpr": fpr[::step].round(4).tolist(), "tpr": tpr[::step].round(4).tolist()},
            "importance": [{"feature": f, "importance": round(float(v), 5)} for f, v in imp[:20]],
            "false_positive_rate_on_real_legit_urls": sanity_fp,
            "recall_on_handwritten_phish_urls": sanity_rec,
        }
        meta[key] = (best, table[best]["test"])

    results["sanity_legit_urls"] = SANITY_LEGIT
    results["sanity_phish_urls"] = SANITY_PHISH
    with open(os.path.join(RESULTS, "metrics.json"), "w") as f:
        json.dump(results, f, indent=2)

    log("\n[4/5] Generating evaluation plots")
    try:
        fig, ax = plt.subplots(1, 2, figsize=(13, 5))
        for key, c in [("host", "#2b6cb0"), ("full", "#c53030")]:
            if key not in results["feature_sets"]:
                continue
            r = results["feature_sets"][key]
            ax[0].plot(r["roc"]["fpr"], r["roc"]["tpr"], color=c, lw=2,
                       label=f"{r['label']} (AUC {meta[key][1]['roc_auc']:.4f})")
        ax[0].plot([0, 1], [0, 1], "k--", lw=0.8)
        ax[0].set(xlabel="False Positive Rate", ylabel="True Positive Rate", title="ROC Curve (Unseen Domains Test Set)")
        ax[0].legend(loc="lower right", fontsize=8)
        ax[0].grid(alpha=0.3)

        imp = results["feature_sets"]["host"]["importance"][:12][::-1]
        ax[1].barh([i["feature"] for i in imp], [i["importance"] for i in imp], color="#2b6cb0")
        ax[1].set(title="Feature Importance (Deployed Host Model)", xlabel="Permutation F1 drop")
        ax[1].grid(axis="x", alpha=0.3)

        plt.tight_layout()
        plt.savefig(os.path.join(RESULTS, "roc_importance.png"), dpi=150)
        plt.close()
        log("  ROC and importance plots saved to results/roc_importance.png")
    except Exception as exc:
        log(f"  Plot skipped: {exc}")

    log("\n[5/5] Final Model Summary (Unseen Domains Hold-Out Test Set)")
    for key, (best, t) in meta.items():
        log(f"  {key.upper():5s} [{best:22s}] Acc={t['accuracy']:.4f} | Prec={t['precision']:.4f} | Rec={t['recall']:.4f} | F1={t['f1']:.4f} | ROC-AUC={t['roc_auc']:.4f} | FPR={t['false_positive_rate']:.4f}")

    h_metrics = results["feature_sets"]["host"]
    log(f"  Host model FPR on {len(SANITY_LEGIT)} diverse real legitimate URLs = {h_metrics['false_positive_rate_on_real_legit_urls']:.1%}")
    log(f"  Host model Recall on {len(SANITY_PHISH)} handwritten phishing URLs = {h_metrics['recall_on_handwritten_phish_urls']:.1%}")
    log_file.close()


if __name__ == "__main__":
    main()
