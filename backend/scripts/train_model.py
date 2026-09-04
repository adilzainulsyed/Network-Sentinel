import os
import sys
import json
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))

def main():
    dataset_path = os.path.join(project_root, "data", "datasets", "full_dataset.csv")
    models_dir = os.path.join(project_root, "backend", "models")
    os.makedirs(models_dir, exist_ok=True)
    
    print(f"Loading dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)
    
    # Preprocessing
    # Drop identifier columns to prevent overfitting
    drop_cols = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
    # Sometimes protocol is kept, but it can be a strong identifier for some attacks. We'll keep it.
    
    X = df.drop(columns=drop_cols + ['label'])
    y = df['label']
    
    # Handle any potential NaNs
    X = X.fillna(0)
    
    # Save the exact feature column list so we can enforce it during inference
    feature_columns = list(X.columns)
    with open(os.path.join(models_dir, "features.json"), "w") as f:
        json.dump(feature_columns, f)
        
    print(f"Features used: {feature_columns}")
    
    # Split: 70% Train, 30% Temp (Test+Val)
    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    # Split Temp: 50% Test, 50% Val (Result: 15% Test, 15% Val)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp)
    
    print(f"Training set: {len(X_train)} samples")
    print(f"Validation set: {len(X_val)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    print("Training RandomForestClassifier...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    
    print("Evaluating on Validation Set...")
    y_val_pred = clf.predict(X_val)
    print("Validation Accuracy:", accuracy_score(y_val, y_val_pred))
    
    print("\nEvaluating on Test Set...")
    y_test_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_test_pred)
    print("Test Accuracy:", acc)
    
    print("\nClassification Report (Test):")
    report = classification_report(y_test, y_test_pred)
    print(report)
    
    # Generate Confusion Matrix
    try:
        import matplotlib
        matplotlib.use('Agg')  # Use non-interactive backend
        import matplotlib.pyplot as plt
        import seaborn as sns
        
        cm = confusion_matrix(y_test, y_test_pred, labels=clf.classes_)
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=clf.classes_, yticklabels=clf.classes_)
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.title('Confusion Matrix')
        cm_path = os.path.join(models_dir, "confusion_matrix.png")
        plt.savefig(cm_path)
        print(f"\nSaved Confusion Matrix plot to {cm_path}")
    except Exception as e:
        print(f"\nWarning: Could not generate confusion matrix plot: {e}")
    
    # Save the model
    model_path = os.path.join(models_dir, "rf_model.joblib")
    joblib.dump(clf, model_path)
    print(f"Saved trained model to {model_path}")

if __name__ == "__main__":
    main()
