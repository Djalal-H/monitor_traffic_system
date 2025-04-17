import pandas as pd
from joblib import load

# (a) Define your feature subset
feature_cols = [
    'frame.time_epoch',
    'radiotap.timestamp.ts',
    'frame.len',
    'wlan_radio.data_rate',
    'wlan_radio.duration',
    'frame.time_relative',
    'wlan_radio.signal_dbm',
    'frame.time_delta_displayed',
    'frame.time_delta',
    'wlan.duration'
]

# 2) Hard‑coded medians (as floats)
DEFAULTS = {
    'frame.time_epoch':            1.608066e+09,
    'radiotap.timestamp.ts':       2.906511e+09,
    'frame.len':                   1.580000e+02,
    'wlan_radio.data_rate':        5.200000e+01,
    'wlan_radio.duration':         4.500000e+01,
    'frame.time_relative':         4.896642e+02,
    'wlan_radio.signal_dbm': -3.900000e+01,
    'frame.time_delta_displayed':  5.400000e-05,
    'frame.time_delta':            5.400000e-05,
    'wlan.duration':               4.800000e+01
}


def preprocess_capture(df: pd.DataFrame) -> pd.DataFrame:
    """
    1. Subset to FEATURE_COLS
    2. Coerce all to numeric (invalid → NaN)
    3. Fill any NaNs with the hard‑coded DEFAULTS
    4. Ensure float64 dtype
    """
    # a) Work on a copy
    df = df.copy()

    # b) Subset (this also drops any extra columns)
    df = df.reindex(columns=feature_cols)

    # c) Coerce everything to numeric, invalid entries become NaN
    df = df.apply(pd.to_numeric, errors='coerce')

    # d) Fill NaNs with your defaults
    df = df.fillna(DEFAULTS)

    # e) Enforce float64 dtype (optional since default is float64)
    df = df.astype('float64')

    return df


def make_predictions(input_csv="captured_packets.csv", model_path='./rf_attacks.joblib', output_csv='predictions.csv'):
    # Load the model
    rf_model = load(model_path)

    # Load the captured packets data
    raw = pd.read_csv(input_csv)

    # Preprocess the data
    X_ready = preprocess_capture(raw)

    # Perform predictions and get probabilities
    y_pred_proba = rf_model.predict_proba(X_ready)

    # Save predictions and probabilities to a CSV file
    X_ready['predictions'] = rf_model.predict(X_ready)
    X_ready['confidence'] = y_pred_proba.max(axis=1)  # Maximum probability as confidence
    X_ready.to_csv(output_csv, index=False)
    print(f"Predictions with confidence saved to {output_csv}")


def load_predictions(input_csv="predictions.csv"):
    predictions = pd.read_csv(input_csv)
    return predictions
