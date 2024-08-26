# Dropbox upload script #

## Overview ##
Used to back files up to a Dropbox instance.

## Workflow ##
Loops over a given directory and searches for files with a specified extension.
Uploads file in a loop - if the upload has been successful for a given file,
its absolute path is appended to a file and it's moved to a different directory.
When the script runs again, those files present in the uploaded log file are not
uploaded.