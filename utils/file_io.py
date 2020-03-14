import pandas as pd

# Read top 50 ports txt file
def get_top_50_ports():
    return pd.read_csv(
        './data/port_list_top_50.txt',
        names=['port', 'description'],
        delimiter=':'
        )

# Read all known ports txt file
def get_all_ports():
    return pd.read_csv(
        './data/port_list_all.txt',
        names=['port', 'description'],
        delimiter=':'
        )

# Read any file
def read_file(filename):
    return pd.read_csv(filename, names=['data'])

# Save dataframe to csv
def save_csv(output):
    output.to_csv('output.csv', encoding='utf-8', index=None, header=True)