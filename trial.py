import pandas as pd

# Load the CSV file
file_path = "complex_synthetic_data.csv"  # Make sure this path is correct
df = pd.read_csv(file_path)

# Check the class distribution for each column
for column in df.columns:
    class_distribution = df[column].value_counts()
    print(f"Class distribution for column {column}:")
    print(class_distribution)
    print()
