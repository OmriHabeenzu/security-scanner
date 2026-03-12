"""
Machine Learning Model Training for Malware Detection
Using NSL-KDD dataset for Intrusion Detection
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import joblib
import os

class MalwareDetectionTrainer:
    """Train and evaluate ML models for malware detection"""
    
    def __init__(self, data_path=None):
        self.models = {}
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.feature_names = []
        
    def load_nsl_kdd_dataset(self, train_path, test_path):
        """
        Load NSL-KDD dataset
        Download from: https://www.unb.ca/cic/datasets/nsl.html
        """
        print("Loading NSL-KDD dataset...")
        
        # Column names for NSL-KDD
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
        ]
        
        # Load datasets
        train_df = pd.read_csv(train_path, names=columns)
        test_df = pd.read_csv(test_path, names=columns)
        
        print(f"Training set: {train_df.shape}")
        print(f"Test set: {test_df.shape}")
        
        return train_df, test_df
    
    def preprocess_data(self, train_df, test_df, binary=True):
        """
        Preprocess NSL-KDD data
        binary=True: Normal vs Attack (2 classes)
        binary=False: Multi-class classification
        """
        print("\nPreprocessing data...")
        
        # Combine for consistent encoding
        combined_df = pd.concat([train_df, test_df], ignore_index=True)
        
        # Convert labels to binary (Normal vs Attack)
        if binary:
            combined_df['label'] = combined_df['label'].apply(
                lambda x: 0 if x == 'normal' else 1
            )
        else:
            # Multi-class: Normal, DoS, Probe, R2L, U2R
            attack_mapping = {
                'normal': 'normal',
                'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS', 
                'smurf': 'DoS', 'teardrop': 'DoS', 'apache2': 'DoS', 'udpstorm': 'DoS',
                'processtable': 'DoS', 'worm': 'DoS', 'mailbomb': 'DoS',
                'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 
                'satan': 'Probe', 'mscan': 'Probe', 'saint': 'Probe',
                'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 
                'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L',
                'warezmaster': 'R2L', 'sendmail': 'R2L', 'named': 'R2L', 
                'snmpgetattack': 'R2L', 'snmpguess': 'R2L', 'xlock': 'R2L', 
                'xsnoop': 'R2L', 'httptunnel': 'R2L',
                'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 
                'rootkit': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R'
            }
            combined_df['label'] = combined_df['label'].map(attack_mapping)
            combined_df['label'] = self.label_encoder.fit_transform(combined_df['label'])
        
        # Drop difficulty column
        combined_df = combined_df.drop('difficulty', axis=1)
        
        # Encode categorical features
        categorical_cols = ['protocol_type', 'service', 'flag']
        for col in categorical_cols:
            le = LabelEncoder()
            combined_df[col] = le.fit_transform(combined_df[col])
        
        # Separate features and labels
        X = combined_df.drop('label', axis=1)
        y = combined_df['label']
        
        # Split back to train and test
        train_size = len(train_df)
        X_train = X[:train_size]
        y_train = y[:train_size]
        X_test = X[train_size:]
        y_test = y[train_size:]
        
        # Scale features
        X_train = self.scaler.fit_transform(X_train)
        X_test = self.scaler.transform(X_test)
        
        self.X_train = X_train
        self.X_test = X_test
        self.y_train = y_train
        self.y_test = y_test
        
        print(f"Training features shape: {X_train.shape}")
        print(f"Training labels: {np.unique(y_train, return_counts=True)}")
        
        return X_train, X_test, y_train, y_test
    
    def train_random_forest(self, n_estimators=100, max_depth=20):
        """Train Random Forest Classifier"""
        print("\n=== Training Random Forest ===")
        
        rf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=42,
            n_jobs=-1,
            verbose=1
        )
        
        rf.fit(self.X_train, self.y_train)
        self.models['random_forest'] = rf
        
        return rf
    
    def train_decision_tree(self, max_depth=20):
        """Train Decision Tree Classifier"""
        print("\n=== Training Decision Tree ===")
        
        dt = DecisionTreeClassifier(
            max_depth=max_depth,
            random_state=42
        )
        
        dt.fit(self.X_train, self.y_train)
        self.models['decision_tree'] = dt
        
        return dt
    
    def train_svm(self, kernel='rbf', sample_size=10000):
        """Train SVM (on subset due to computational cost)"""
        print("\n=== Training SVM (on subset) ===")
        
        # Use subset for SVM due to computational complexity
        indices = np.random.choice(len(self.X_train), min(sample_size, len(self.X_train)), replace=False)
        X_train_subset = self.X_train[indices]
        y_train_subset = self.y_train.iloc[indices]
        
        svm = SVC(
            kernel=kernel,
            random_state=42,
            verbose=True
        )
        
        svm.fit(X_train_subset, y_train_subset)
        self.models['svm'] = svm
        
        return svm
    
    def evaluate_model(self, model_name):
        """Evaluate a trained model"""
        print(f"\n=== Evaluating {model_name.upper()} ===")
        
        model = self.models[model_name]
        y_pred = model.predict(self.X_test)
        
        accuracy = accuracy_score(self.y_test, y_pred)
        precision = precision_score(self.y_test, y_pred, average='weighted', zero_division=0)
        recall = recall_score(self.y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(self.y_test, y_pred, average='weighted', zero_division=0)
        
        print(f"\nAccuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"Precision: {precision:.4f}")
        print(f"Recall:    {recall:.4f}")
        print(f"F1-Score:  {f1:.4f}")
        
        print("\nClassification Report:")
        print(classification_report(self.y_test, y_pred))
        
        print("\nConfusion Matrix:")
        print(confusion_matrix(self.y_test, y_pred))
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'predictions': y_pred
        }
    
    def save_models(self, output_dir='ml_models'):
        """Save trained models and scaler"""
        os.makedirs(output_dir, exist_ok=True)
        
        print(f"\nSaving models to {output_dir}/...")
        
        for model_name, model in self.models.items():
            filepath = os.path.join(output_dir, f'{model_name}.pkl')
            joblib.dump(model, filepath)
            print(f"✓ Saved {model_name}")
        
        # Save scaler
        scaler_path = os.path.join(output_dir, 'scaler.pkl')
        joblib.dump(self.scaler, scaler_path)
        print(f"✓ Saved scaler")
        
        print("\nModels saved successfully!")


def main():
    """Main training pipeline"""
    
    print("=" * 60)
    print("MALWARE DETECTION - ML MODEL TRAINING")
    print("=" * 60)
    
    # Initialize trainer
    trainer = MalwareDetectionTrainer()
    
    # IMPORTANT: Update these paths to your NSL-KDD dataset location
    TRAIN_PATH = 'data/KDDTrain+.txt'
    TEST_PATH = 'data/KDDTest+.txt'
    
    print("\n📥 Step 1: Download NSL-KDD Dataset")
    print("Download from: https://www.unb.ca/cic/datasets/nsl.html")
    print(f"Place files at: {TRAIN_PATH} and {TEST_PATH}")
    
    # Check if files exist
    if not os.path.exists(TRAIN_PATH) or not os.path.exists(TEST_PATH):
        print("\n❌ ERROR: Dataset files not found!")
        print("Please download the NSL-KDD dataset first.")
        return
    
    # Load dataset
    train_df, test_df = trainer.load_nsl_kdd_dataset(TRAIN_PATH, TEST_PATH)
    
    # Preprocess
    trainer.preprocess_data(train_df, test_df, binary=True)
    
    # Train models
    print("\n" + "=" * 60)
    print("TRAINING MODELS")
    print("=" * 60)
    
    trainer.train_random_forest(n_estimators=100, max_depth=20)
    trainer.train_decision_tree(max_depth=20)
    trainer.train_svm(sample_size=10000)
    
    # Evaluate all models
    print("\n" + "=" * 60)
    print("MODEL EVALUATION")
    print("=" * 60)
    
    results = {}
    for model_name in trainer.models.keys():
        results[model_name] = trainer.evaluate_model(model_name)
    
    # Summary
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    
    for model_name, metrics in results.items():
        print(f"\n{model_name.upper()}:")
        print(f"  Accuracy: {metrics['accuracy']*100:.2f}%")
        print(f"  F1-Score: {metrics['f1_score']:.4f}")
    
    # Save models
    trainer.save_models('ml_models')
    
    print("\n" + "=" * 60)
    print("✅ TRAINING COMPLETE!")
    print("=" * 60)


if __name__ == "__main__":
    main()
