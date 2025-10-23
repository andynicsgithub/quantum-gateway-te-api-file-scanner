# te_api
A Python client side utility for using Threat Emulation API calls to an on-premises Check Point gateway (or Threat Emulation appliance).

The utility will parse a directory tree, and use the Threat Emulation API to scan the files.
Files will be moved from the source or "input" directory to one of the following directories:
- Benign files will be moved to the "benign" directory.
- Malicious files will be moved to the "quarantine" directory.
- Files that can't be correctly processed will be moved to the "error" directory.

Logs for all files plus reports for malicious files will be downloaded and placed in the "reports" directory.

Normal files, i.e. files that are not archives, will be processed in a parallel fashion. Change the "concurrency" value to suit the capacity of your environment to avoid overloading or slowing down the processing of files from other sources.

If processed in an on-premises Threat Emulation appliance, archives are expanded and all files within them are analysed. This can lead to very large numbers of files bieng processed at once, so archive files are processed one at a time after the normal files. If one or more files in the archive are found malicious, the parent archive file is marked as malicious.

Note that this utility will move files from the input directory to the output directories, leaving the input directory empty.
If your use case requires that benign files be left in the input directory and only malicious files be moved to the quarantine, a different approach is needed.

### The flow
Going through the input directory and handling each file in order to get its Threat Emulation results.
Directory tree structure below the input directory will be reproduced in the bening directory.

For each file:

      1. Compute SHA1 hash and query the cache of recently analysed files for existing verdict.

           If results exist then goto #4, otherwise- continue to #2
    
      2. Upload the file to the appliance for te and te_eb features.
    
      3. If upload result is upload_success then wait and query until verdict is available.

           (Note, te_eb results of early malicious verdict might be received earlier during the queries in between)
    
      4. Write the log file and place it in the reports dir. Move the file to the benign or quarantine dir.
    
      5. If verdict is malicious then also download the TE report and place it in the reports dir.





### Usage
~~~~
Recommended: Edit the values in _config.ini.default_ to suit your environment, then change the name to _config.ini_.


python te_api.py --help

usage: te_api.py [-h] [-id] [-od] [-ip]

optional arguments:
  -h        --help                  show this help message and exit
  -rep		--reports_directory		the output folder for logs and reports
  -in		--input_directory		the input directory of files to be scanned
  -ip		--appliance_ip			the appliance ip address
  -n		--concurrency			(integer) Number of files to process in parallel
  -out		--benign_directory		the directory for Benign files after scanning
  -jail		--quarantine_directory	the directory for Malicious files after scanning
  -error	--error_directory		the directory for files which cause a scanning error

For ease of use these arguments may be set in the file config.ini, or by editing te_api.py.
Defaults in te_api.py are overridden by values in config.ini.
Command-line arguments will override both defaults in the .py file and values in config.ini.


### References
* Additional Threat Emulation API info: [sk167161](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk167161)
* te_eb feature: [sk117168 chapter 4](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk117168#New%20Public%20API%20Interface)
