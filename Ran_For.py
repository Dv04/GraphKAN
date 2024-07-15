import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler

# Define the main directory path
main_folder_path = "CICIoMT2024/WiFI_and_MQTT/"


# Function to load CSV files into DataFrames with labels
def load_and_label_csv(file_path, label):
    # print(f"Reading file: {file_path}")
    df = pd.read_csv(file_path)
    df["Label"] = label
    return df


# Function to traverse directories and load CSV files with labels
def load_csv_files_with_labels(folder_path, label_mapping):
    all_data = pd.DataFrame()
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".csv"):
                file_path = os.path.join(root, file)
                label = label_mapping.get(file)
                if label is not None:
                    # print(f"Loading file: {file_path} with label: {label}")
                    df = load_and_label_csv(file_path, label)
                    all_data = pd.concat([all_data, df], ignore_index=True)
    return all_data


# Define label mappings
label_mapping_profiling = {
    file: 0 for file in os.listdir(os.path.join(main_folder_path, "profiling/CSV"))
}
label_mapping_attacks_test = {
    file: 1 for file in os.listdir(os.path.join(main_folder_path, "attacks/csv/test"))
}
label_mapping_attacks_train = {
    file: 1 for file in os.listdir(os.path.join(main_folder_path, "attacks/csv/train"))
}

# Combine all label mappings
label_mapping = {
    **label_mapping_profiling,
    **label_mapping_attacks_test,
    **label_mapping_attacks_train,
}

print("Loading profiling data (benign)...")
# Load the profiling CSV files (benign)
profiling_folder_path = os.path.join(main_folder_path, "profiling/CSV")
profiling_data = load_csv_files_with_labels(
    profiling_folder_path, label_mapping_profiling
)

print("Loading attack data (malicious)...")
# Load the attack CSV files (malicious)
attack_folder_path_test = os.path.join(main_folder_path, "attacks/csv/test")
attack_folder_path_train = os.path.join(main_folder_path, "attacks/csv/train")

attack_data_test = load_csv_files_with_labels(
    attack_folder_path_test, label_mapping_attacks_test
)
attack_data_train = load_csv_files_with_labels(
    attack_folder_path_train, label_mapping_attacks_train
)

print("Combining data...")
# Combine the data
combined_data = pd.concat(
    [profiling_data, attack_data_test, attack_data_train], ignore_index=True
)

print("Preprocessing data...")
# Preprocess the data
# Handling missing values by filling them with the mean of the column
combined_data.fillna(combined_data.mean(), inplace=True)

# Feature Selection: Drop columns that are not useful for classification
irrelevant_columns = ["Label"]  # Add any other non-numeric columns if needed
X = combined_data.drop(columns=irrelevant_columns)
y = combined_data["Label"]

print("Standardizing data...")
# Standardize the data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

print("Splitting data into training and testing sets...")
# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42
)
print(X_train, X_test)
print(y_train, y_test)

print("Training Random Forest Classifier...")
# Train a Random Forest Classifier
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

print("Predicting on the test set...")
# Predict on the test set
y_pred = clf.predict(X_test)

print("Printing classification report and accuracy...")
# Print classification report and accuracy
print("Classification Report:")
print(classification_report(y_test, y_pred))

print("Accuracy:", accuracy_score(y_test, y_pred))

print("Finished!")
