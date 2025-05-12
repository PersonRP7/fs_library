# Library backup service #

## Overview ##
This service handles the automatic backups of an internal file based library.
It uses dropbox as the backend by handling several segments:
 - Automated file discovery
 - Application logging
 - Automated status based file movement / tracking
 - Automated API token refreshment
 - File naming standardization

## Deployment ##
The script's key components are provisioned through an .env file
Create a virtual environment:

```python -m venv env```
Activate the virtual environment:

```.\env\Scripts\Activate.ps1```
Provision the .env file:

Observe the ```.env_example```.

Inside the directory specified under the ```CURRENT_DIRECTORY```,
there should be three directories named: ```processed```, ```to_send```, ```uploaded```

Run the script: ```python main.py```


## Mechanism of action ##
Loops over a given directory and searches for files with a specified extension.
Uploads file in a loop - if the upload has been successful for a given file,
its absolute path is appended to a file and it's moved to a different directory.
When the script runs again, those files present in the uploaded log file are not
uploaded.