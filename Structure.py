import os


def print_folder_structure(folder_path, indent=0):
    # Ensure the folder path is absolute
    folder_path = os.path.abspath(folder_path)

    # Iterate over the directories and files in the folder
    for root, dirs, files in os.walk(folder_path):
        # Calculate current level of indentation
        level = root.replace(folder_path, "").count(os.sep)
        indent = " " * 4 * level

        print(f"{indent}{level}. {os.path.basename(root)}/")
        subindent = " " * 4 * (level + 1)
        for f in files:
            if f.endswith(".csv"):
                continue
            print(f"{subindent}{level+1}. {f}")


if __name__ == "__main__":
    user_folder_path = input("Enter the main folder path: ")
    print_folder_structure(user_folder_path)

# import os
# import pandas as pd

# # Define the main directory path
# main_folder_path = "CICIoMT2024"

# # Define the output file path
# output_file_path = "output.txt"

# # Adjust pandas display options
# pd.set_option("display.max_columns", None)  # Show all columns
# # pd.set_option('display.max_rows', None)     # Show all rows
# pd.set_option("display.max_colwidth", None)  # Do not truncate column contents


# # Function to get column names and sample data from a CSV file
# def get_csv_info(file_path):
#     try:
#         df = pd.read_csv(file_path)
#         columns = df.columns.tolist()
#         sample_data = df.head().to_string(index=False)
#         return columns, sample_data
#     except Exception as e:
#         print(f"Error reading {file_path}: {e}")
#         return [], None


# # Function to write output to a file
# def write_output(file_path, text):
#     try:
#         with open(file_path, "a") as file:
#             file.write(text)
#     except Exception as e:
#         print(f"Error writing to {file_path}: {e}")


# # Function to traverse directories and process CSV files
# def process_csv_files(folder_path):
#     for root, dirs, files in os.walk(folder_path):
#         for file in files:
#             if file.endswith(".csv"):
#                 file_path = os.path.join(root, file)
#                 print(f"Processing file: {file_path}")
#                 columns, sample_data = get_csv_info(file_path)
#                 output_text = f"File: {file_path}\nColumns: {columns}\nSample Data:\n{sample_data}\n\n"
#                 write_output(output_file_path, output_text)


# # Process CSV files in the profiling directory
# print("Profiling CSV files:")
# process_csv_files(os.path.join(main_folder_path, "profiling/CSV"))

# # Process CSV files in the attacks directory (both test and train)
# print("Attack CSV files (test):")
# process_csv_files(os.path.join(main_folder_path, "attacks/csv/test"))

# print("Attack CSV files (train):")
# process_csv_files(os.path.join(main_folder_path, "attacks/csv/train"))
