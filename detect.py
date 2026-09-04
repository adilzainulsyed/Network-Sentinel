import os
import sys
import argparse
import joblib
import json
import collections

# Add the current directory to path to ensure backend modules can be imported
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from backend.app.flows.extractor import FlowExtractor
from backend.app.features.extractor import FeatureExtractor

def main():
    parser = argparse.ArgumentParser(description="NTRO Network Threat Detector Inference")
    parser.add_argument("pcap_file", type=str, help="Path to the PCAP file to analyze")
    args = parser.parse_args()

    if not os.path.exists(args.pcap_file):
        print(f"Error: File {args.pcap_file} does not exist.")
        sys.exit(1)

    print(f"Analyzing {args.pcap_file}...")

    # Extract flows
    print("Extracting flows...")
    flow_ext = FlowExtractor()
    flow_ext.process_pcap(args.pcap_file)
    df_flows = flow_ext.to_dataframe()

    if df_flows.empty:
        print("No flows found in the PCAP.")
        return

    print(f"Extracted {len(df_flows)} bidirectional flows.")

    # Extract features
    print("Extracting ML features...")
    feat_ext = FeatureExtractor(df_flows)
    df_features = feat_ext.extract_features()

    # Load model and feature configuration
    models_dir = os.path.join(os.path.dirname(__file__), "backend", "models")
    model_path = os.path.join(models_dir, "rf_model.joblib")
    features_path = os.path.join(models_dir, "features.json")

    if not os.path.exists(model_path) or not os.path.exists(features_path):
        print("Error: Trained model or features.json not found in backend/models/")
        sys.exit(1)

    clf = joblib.load(model_path)
    with open(features_path, "r") as f:
        feature_columns = json.load(f)

    # Prepare data for prediction
    # Ensure missing columns are added with 0s and we only pass the expected columns
    for col in feature_columns:
        if col not in df_features.columns:
            df_features[col] = 0

    X = df_features[feature_columns].fillna(0)

    # Predict
    print("Running detection model...")
    predictions = clf.predict(X)
    
    # Add predictions back to the flows dataframe for detailed output if needed
    df_flows['prediction'] = predictions
    
    # Summarize results
    print("\n--- Detection Results ---")
    counts = collections.Counter(predictions)
    for label, count in counts.items():
        print(f"{label}: {count} flows ({count/len(predictions)*100:.2f}%)")

    # Optionally, you can save the detailed results
    out_csv = args.pcap_file.replace('.pcap', '_alerts.csv')
    # Save a subset of info for the alerts
    alert_cols = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'prediction']
    df_alerts = df_flows[alert_cols]
    df_alerts.to_csv(out_csv, index=False)
    print(f"\nDetailed alerts saved to {out_csv}")

if __name__ == "__main__":
    main()
