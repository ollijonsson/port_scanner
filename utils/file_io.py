import pandas as pd

def get_top_50_ports():
    """ Read top 50 ports file into a dataframe """
    return pd.read_csv(
        './data/port_list_top_50.txt',
        names=['port', 'description'],
        delimiter=':'
        )

def get_all_ports():
    """ Read all known ports file into a dataframe """
    return pd.read_csv(
        './data/port_list_all.txt',
        names=['port', 'description'],
        delimiter=':'
        )

def read_file(filename):
    """ Read a single column file into a dataframe """
    return pd.read_csv(filename, names=['data'])

def save_csv(output):
    """ Save a dataframe to csv file """
    output.to_csv('output.csv', encoding='utf-8', index=None, header=True)