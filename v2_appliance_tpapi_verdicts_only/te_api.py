"""
te_api v2.0
A Python client-side utility for interacting with the Threat Emulation API.
Features:
  - Scan input files in a specified directory
  - Handle TE and TE_EB processing via the appliance
  - Store results in an output directory
  - Support concurrent processing of multiple files. Requires command line argument.
"""

from te_file_handler import TE
import os
import argparse
import concurrent.futures

# Following variables can be assigned and used instead of adding them as arguments when running the te_api.py .
#  input_directory and output_directory have the following default settings.
#  Using the following input directory default setting means - assuming that the input files to handle are in
#   already existing folder :  ..appliance_tpapi/te_api/input_files
#  Using the following output_directory default setting means - creating/using the output directory :
#   ..appliance_tpapi/te_api/te_response_data
input_directory = "input_files"
output_directory = "te_response_data"
appliance_ip = ""


def main():
    """
    1. Get the optional arguments (if any): the input-directory, the output-directory and appliance-ip.
    2. Accordingly set the api-url, and create the output directory.
    3. Go though all input files in the input directory.
        Handling each input file is described in TE class in te_file_handler.py:
    """
    global input_directory
    global output_directory
    global appliance_ip
    global concurrency
    global url
    parser = argparse.ArgumentParser()
    parser.add_argument("-id", "--input_directory", help="the input files folder to be scanned by TE")
    parser.add_argument("-od", "--output_directory", help="the output folder with TE results")
    parser.add_argument("-ip", "--appliance_ip", help="the appliance ip address")
    parser.add_argument('-n', '--concurrency', type=int, help='Number of concurrent loops')
    args = parser.parse_args()
    if args.input_directory:
        input_directory = args.input_directory
    print("The input files directory to be scanned by TE : {}".format(input_directory))
    if not os.path.exists(input_directory):
        print("\n\n  --> The input files directory {} does not exist !\n\n".format(input_directory))
        parser.print_help()
        return
    if args.output_directory:
        output_directory = args.output_directory
    print("The output directory with TE results : {}".format(output_directory))
    if not os.path.exists(output_directory):
        print("Pre-processing: creating te_api output directory {}".format(output_directory))
        try:
            os.mkdir(output_directory)
        except Exception as E1:
            print("could not create te_api output directory, because: {}".format(E1))
            return
    if args.appliance_ip:
        appliance_ip = args.appliance_ip
    if not appliance_ip:
        print("\n\n  --> Missing appliance_ip !\n\n")
        parser.print_help()
        return
    print("The appliance ip address : {}".format(appliance_ip))
    url = "https://" + appliance_ip + ":18194/tecloud/api/v1/file/"


    # A loop over the files in the input folder
    files = os.listdir(input_directory)
    print("Begin handling input files by TE")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        executor.map(handle_file, files)

def handle_file(file_name):
    try:
        full_path = os.path.join(input_directory, file_name)
        print("Handling file: {} by TE".format(file_name))
        te = TE(url, file_name, full_path, output_directory)
        te.handle_file()
    except Exception as E:
        print("Could not handle file: {} because: {}. Continue to handle the next file.".format(file_name, E))


if __name__ == '__main__':
    main()
