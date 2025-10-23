"""
te_api v6.2
A Python client-side utility for interacting with the Threat Emulation API.
Features:
  - Scan input files in a specified directory
  - Handle TE and TE_EB processing via the appliance
  - Store results in an output directory
  - Support concurrent processing of multiple files (via command line argument or config.ini)
  - Move files from source directory to benign_directory, quarantine_directory, or error_directory based on TE verdict

Changes in v6.2 over v6.1:
  - Added handling of an error_directory for files causing scanning errors
  - Minor logging improvements for clarity and consistency
  - No functional changes in file handling or concurrency logic
  - Maintenance / readability updates (pretty-printing, debug messages)
"""

from te_file_handler import TE
import os
import argparse
import multiprocessing
import zipfile
import configparser
import datetime

# Following variables can be assigned and used instead of adding them as arguments when running the te_api.py .
#  input_directory and reports_directory have the following default settings.
#  Using the following input directory default setting means - assuming that the input files to handle are in
#   already existing folder :  ..appliance_tpapi/te_api/input_files
#  Using the following reports_directory default setting means - creating/using the output directory :
#   ..appliance_tpapi/te_api/te_response_data
input_directory = "input_files"
reports_directory = "te_response_data"
appliance_ip = ""
benign_directory = ""
quarantine_directory = ""
error_directory = ""

def main():
    """
    1. Get the optional arguments (if any): the input-directory, the output-directory and appliance-ip.
    2. Accordingly set the api-url, and create the output directory.
    3. Go though all input files in the input directory.
        Handling each input file is described in TE class in te_file_handler.py:
    """
    global input_directory
    global reports_directory
    global appliance_ip
    global benign_directory
    global quarantine_directory
    global error_directory
    global concurrency
    global url
    # Set a default value for concurrency in case something goes wrong
    concurrency = 4  # Change this to your desired default

    # Create a ConfigParser object
    config = configparser.ConfigParser()
    # Read the configuration from 'config.ini'
    config.read('config.ini')

    # Use the values from the configuration file if they exist
    if 'DEFAULT' in config:
        if 'input_directory' in config['DEFAULT']:
            input_directory = config['DEFAULT']['input_directory']
        if 'reports_directory' in config['DEFAULT']:
            reports_directory = config['DEFAULT']['reports_directory']
        if 'appliance_ip' in config['DEFAULT']:
            appliance_ip = config['DEFAULT']['appliance_ip']
        if 'benign_directory' in config['DEFAULT']:
            benign_directory = config['DEFAULT']['benign_directory']
        if 'quarantine_directory' in config['DEFAULT']:
            quarantine_directory = config['DEFAULT']['quarantine_directory']
        if 'error_directory' in config['DEFAULT']:
            error_directory = config['DEFAULT']['error_directory']
        if 'concurrency' in config['DEFAULT']:
            concurrency = int(config['DEFAULT']['concurrency'])
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-in", "--input_directory", help="the input files folder to be scanned by TE")
    parser.add_argument("-rep", "--reports_directory", help="the output folder with TE results")
    parser.add_argument("-ip", "--appliance_ip", help="the appliance ip address")
    parser.add_argument('-n', '--concurrency', type=int, help='Number of concurrent loops')
    parser.add_argument('-out', '--benign_directory', help='the directory to move Benign files after scanning')
    parser.add_argument('-jail', '--quarantine_directory', help='the directory to move Malicious files after scanning')
    parser.add_argument('-error', '--error_directory', help='the directory to move files which cause a scanning error')
    args = parser.parse_args()
    
    if args.appliance_ip:
        appliance_ip = args.appliance_ip

    if not appliance_ip:
        print("\n\n  --> Missing appliance_ip !\n\n")
        parser.print_help()
        return
    print("The appliance ip address : {}".format(appliance_ip))
    url = "https://" + appliance_ip + ":18194/tecloud/api/v1/file/"
    
    if args.input_directory:
        input_directory = args.input_directory
    print("The input files directory to be scanned by TE : {}".format(input_directory))
    if not os.path.exists(input_directory):
        print("\n\n  --> The input files directory {} does not exist !\n\n".format(input_directory))
        parser.print_help()
        return

    if args.reports_directory:
        reports_directory = args.reports_directory
    print("The output directory with TE results : {}".format(reports_directory))
    if not os.path.exists(reports_directory):
        print("Pre-processing: creating te_api output directory {}".format(reports_directory))
        try:
            os.mkdir(reports_directory)
        except Exception as E1:
            print("could not create te_api output directory, because: {}".format(E1))
            return

    if args.benign_directory:
        benign_directory = args.benign_directory
    print("The output directory for Benign files: {}".format(benign_directory))
    if not os.path.exists(benign_directory):
        print("Pre-processing: creating Benign directory {}".format(benign_directory))
        try:
            os.mkdir(benign_directory)
        except Exception as E1:
            print("could not create Benign directory because: {}".format(E1))
            return

    if args.quarantine_directory:
        quarantine_directory = args.quarantine_directory
    if not os.path.exists(quarantine_directory):
        print("Pre-processing: creating Benign directory {}".format(quarantine_directory))
        try:
            os.mkdir(quarantine_directory)
        except Exception as E1:
            print("could not create Quarantine directory because: {}".format(E1))
            return
    print("The output directory for Malicious files: {}".format(quarantine_directory))
 
    if args.error_directory:
        error_directory = args.error_directory
    if not os.path.exists(error_directory):
        print("Pre-processing: creating Benign directory {}".format(error_directory))
        try:
            os.mkdir(error_directory)
        except Exception as E1:
            print("could not create error directory because: {}".format(E1))
            return
    print("The output directory for Error files: {}".format(error_directory))
 
    if args.concurrency:
        concurrency = args.concurrency
    
    print("Parallel processing of {} files at once".format(concurrency))
    
    # Define the list of archive file extensions
    archive_extensions = [".7z", ".arj", ".bz2", ".CAB", ".dmg", ".gz", ".img", ".iso", ".msi", ".pkg", ".rar", ".tar", ".tbz2", ".tbz", ".tb2", ".tgz", ".xz", ".zip", ".udf", ".qcow2"]

    # A loop over the files in the input folder
    files = os.listdir(input_directory)
    print("Begin handling input files by TE")

    # Separate archive files and other files
    archive_files = []
    other_files = []

    for file_name in files:
        full_path = os.path.join(input_directory, file_name)
        extension = os.path.splitext(file_name)[1]
        if extension.lower() in archive_extensions:
            archive_files.append(file_name)
        else:
            other_files.append(file_name)

    # Print out the number of archive and non-archive files
    print("There are {} archive files and {} non-archive files".format(len(archive_files), len(other_files)))

    # Process other files concurrently
    print(f"Value of concurrency before parallel processing: {concurrency}")
    with multiprocessing.Pool(concurrency) as pool:
        pool.map(process_files, other_files)

    # Process archive files sequentially
    for file_name in archive_files:
        process_files(file_name)

def print_with_timestamp(message, variable):
    now = datetime.datetime.now()
    timestamp = now.strftime("%H:%M:%S.%f")
    print("{} - {}".format(timestamp, message.format(variable)))

def process_files(file_name):
    try:
        full_path = os.path.join(input_directory, file_name)
        print_with_timestamp("Handling file: {} by TE",file_name)
        te = TE(url, file_name, full_path, reports_directory, benign_directory, quarantine_directory, error_directory)
        te.handle_file()
    except Exception as E:
        print("Could not handle file: {} because: {}. Continue to handle the next file.".format(file_name, E))

if __name__ == '__main__':
    main()
