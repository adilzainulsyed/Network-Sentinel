import os
import sys
import pandas as pd
from pathlib import Path

# Fix python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from backend.app.flows.extractor import FlowExtractor
from backend.app.features.extractor import FeatureExtractor

def main():
    pcaps_dir = os.path.join(project_root, "data", "pcaps")
    datasets_dir = os.path.join(project_root, "data", "datasets")
    os.makedirs(datasets_dir, exist_ok=True)
    
    output_file = os.path.join(datasets_dir, "full_dataset.csv")
    
    all_dfs = []
    
    # Iterate through all pcap files
    for pcap_file in Path(pcaps_dir).glob("*.pcap"):
        label = pcap_file.stem.upper()
        print(f"Processing {pcap_file.name} as {label}...")
        
        # Extract flows
        flow_ext = FlowExtractor()
        flow_ext.process_pcap(str(pcap_file))
        df_flows = flow_ext.to_dataframe()
        
        if df_flows.empty:
            print(f"No flows found in {pcap_file.name}")
            continue
            
        # Extract features
        feat_ext = FeatureExtractor(df_flows)
        df_features = feat_ext.extract_features()
        
        # Assign label
        df_features = df_features.copy()
        df_features['label'] = label
        
        all_dfs.append(df_features)
        
    if not all_dfs:
        print("No data extracted. Exiting.")
        return
        
    # Combine and save
    full_df = pd.concat(all_dfs, ignore_index=True)
    full_df.to_csv(output_file, index=False)
    
    print(f"Successfully saved {len(full_df)} total labeled flows to {output_file}")

if __name__ == "__main__":
    main()
