from dotenv import load_dotenv
import os
import requests
import json
import logging
import sys
from typing import Union
from pathlib import Path

# Load environment variables from .env file
load_dotenv()

# Retrieve environment variables
API_KEY = os.getenv("API_KEY")
API_ADDRESS = os.getenv("API_ADDRESS")
API_REFRESH_ADDRESS = os.getenv("API_REFRESH_ADDRESS")
DROPBOX_PATH = os.getenv("DROPBOX_PATH")
APP_KEY = os.getenv("APP_KEY")
APP_SECRET = os.getenv("APP_SECRET")
REFRESH_TOKEN = os.getenv("REFRESH_TOKEN")
DROPBOX_DIR = os.getenv("DROPBOX_DIR")
UPLOADED_FILES_LOG = os.getenv("UPLOADED_FILES_LOG")

# Set up logging to both file and stdout
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler(sys.stdout)],
)


def get_new_short_token(
    api_refresh_address: str, refresh_token: str, app_key: str, app_secret: str
) -> str | dict:
    """
    Request a new short-lived access token using the refresh token.

    Args:
        api_refresh_address (str): The API endpoint for refreshing the token.
        refresh_token (str): The refresh token provided by Dropbox.
        app_key (str): The application key provided by Dropbox.
        app_secret (str): The application secret provided by Dropbox.

    Returns:
        str | dict: The new access token as a string if successful, or a dictionary with error details.
    """
    data = {
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
        "client_id": app_key,
        "client_secret": app_secret,
    }

    try:
        logging.info("Requesting new short-lived access token...")
        response = requests.post(api_refresh_address, data=data, timeout=10)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)

        logging.info(
            f"Token successfully retrieved with status code {response.status_code}."
        )
        return response.json()  # Assuming the response is JSON formatted

    except requests.exceptions.HTTPError as http_err:
        logging.error(
            f"HTTP error occurred: {http_err} - Status code: {response.status_code}"
        )
        return {"status": "error", "description": f"HTTP error: {http_err}"}

    except requests.exceptions.ConnectionError as conn_err:
        logging.error(f"Connection error occurred: {conn_err}")
        return {"status": "error", "description": f"Connection error: {conn_err}"}

    except requests.exceptions.Timeout as timeout_err:
        logging.error(f"Timeout error occurred: {timeout_err}")
        return {"status": "error", "description": f"Timeout error: {timeout_err}"}

    except requests.exceptions.RequestException as req_err:
        logging.error(f"An error occurred during the request: {req_err}")
        return {"status": "error", "description": f"Request error: {req_err}"}


def read_file(file_path: str, mode: str) -> Union[str, bytes, dict]:
    """
    Read a file into memory. The `rb` mode is used when sending the actual
    payload due to Dropbox API specifications.

    Parameters:
        file_path (str): The path to the file to be read.
        mode (str): File open mode. `r` for read, `rb` for read binary.

    Returns:
        Union[str, bytes, dict]: The content of the file if successful. Returns a string
            if the mode is `r`, and bytes if the mode is `rb`. Returns a dictionary with
            error details if an exception occurs.

    Raises:
        Exception: If any error occurs during file reading.
    """
    try:
        logging.info(f"Attempting to read file: {file_path}")
        with open(file_path, mode) as f:
            file_content = f.read()
        logging.info(f"File read successfully: {file_path}")
        return file_content

    except FileNotFoundError as fnf_error:
        logging.error(f"File not found: {fnf_error}")
        return {"status": "error", "description": f"File not found: {fnf_error}"}

    except IsADirectoryError as dir_error:
        logging.error(f"Expected a file but found a directory: {dir_error}")
        return {"status": "error", "description": f"Is a directory: {dir_error}"}

    except IOError as io_error:
        logging.error(f"I/O error occurred: {io_error}")
        return {"status": "error", "description": f"I/O error: {io_error}"}

    except Exception as e:
        logging.error(f"An error occurred while reading the file: {e}")
        return {"status": "error", "description": f"Error: {e}"}


def extract_filename(file_path: str) -> str:
    """
    Extracts the filename from an absolute file path.

    Args:
        file_path (str): The absolute path to the file.

    Returns:
        str: The filename extracted from the path.

    Raises:
        ValueError: If the provided file path is not a valid string.
    """
    try:
        filename = Path(file_path).name
        return filename
    except TypeError as e:
        logging.error(f"TypeError: Provided file path is not a correct string - {e}")
        raise ValueError("Incorrect file path provided; it must be a string.") from e
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise


def check_uploaded_log(file_path: str) -> bool:
    """
    Check if a file has already been uploaded by looking up its path in the log file.
    If the log file does not exist, create it.

    Args:
        file_path (str): The absolute path of the file to check.

    Returns:
        bool: True if the file is already logged as uploaded, False otherwise.
    """
    try:
        with open(UPLOADED_FILES_LOG, "r") as log_file:
            uploaded_files = log_file.readlines()
            uploaded_files = [line.strip() for line in uploaded_files]
        return file_path in uploaded_files
    except FileNotFoundError:
        # If the log file does not exist, create it
        logging.info("Uploaded files log does not exist. Creating log file.")
        with open(UPLOADED_FILES_LOG, "w") as log_file:
            pass  # Create the file
        return False
    except Exception as e:
        logging.error(f"Error checking uploaded files log: {e}")
        return False


def log_uploaded_file(file_path: str):
    """
    Append the file path to the uploaded files log.

    Args:
        file_path (str): The absolute path of the file to log as uploaded.
    """
    try:
        with open(UPLOADED_FILES_LOG, "a") as log_file:
            log_file.write(f"{file_path}\n")
        logging.info(f"Logged uploaded file: {file_path}")
    except Exception as e:
        logging.error(f"Error logging uploaded file: {e}")


def send_file(
    local_file: str, short_token_file: str, dropbox_dir: str, api_address: str
) -> dict:
    """
    Send a file to Dropbox using the Dropbox API. If the token is expired,
    generates a new token and retries the upload once.

    Args:
        local_file (str): The path to the local file to upload.
        short_token_file (str): The path to the file containing the Dropbox short-lived access token.
        dropbox_dir (str): The directory in Dropbox where the file should be uploaded.
        api_address (str): The API endpoint for uploading the file.

    Returns:
        dict: A dictionary indicating the status of the upload and any error messages.
    """
    # Check if the file has already been uploaded
    if check_uploaded_log(local_file):
        logging.info(f"File {local_file} has already been uploaded. Skipping.")
        return {
            "status": "skipped",
            "description": f"File {local_file} has already been uploaded.",
        }

    retries = 0
    max_retries = 1

    while retries <= max_retries:
        # Read the short-lived token from file
        short_token_result = read_file(short_token_file, "r")
        if (
            isinstance(short_token_result, dict)
            and short_token_result.get("status") == "error"
        ):
            logging.error(
                f"Failed to read short token: {short_token_result['description']}"
            )
            return {"status": "error", "description": "Failed to read short token"}

        short_token = (
            short_token_result.strip()
        )  # Strip any extraneous whitespace/newline characters

        # Prepare Dropbox-API-Arg header
        dropbox_arg = {
            "autorename": False,
            "mode": "add",
            "mute": False,
            "path": f"{dropbox_dir}/{extract_filename(local_file)}",
            "strict_conflict": False,
        }

        headers = {
            "Authorization": f"Bearer {short_token}",
            "Content-Type": "application/octet-stream",
            "Dropbox-API-Arg": json.dumps(dropbox_arg),
        }

        # Read the local file content
        file_content_result = read_file(local_file, "rb")
        if (
            isinstance(file_content_result, dict)
            and file_content_result.get("status") == "error"
        ):
            logging.error(
                f"Failed to read local file: {file_content_result['description']}"
            )
            return {"status": "error", "description": "Failed to read local file"}

        file_content = file_content_result

        # Attempt to send the file via the API
        try:
            logging.info(
                f"Uploading file: {local_file} to Dropbox directory: {dropbox_dir}"
            )
            response = requests.post(
                api_address, headers=headers, data=file_content, timeout=10
            )

            if response.status_code == 401 and retries < max_retries:
                logging.warning(
                    "Token expired or unauthorized. Attempting to refresh token..."
                )
                # Get a new short token and write it to the short token file
                token_result = get_new_short_token(
                    API_REFRESH_ADDRESS, REFRESH_TOKEN, APP_KEY, APP_SECRET
                )
                if (
                    isinstance(token_result, dict)
                    and token_result.get("status") == "error"
                ):
                    logging.error(
                        f"Failed to refresh token: {token_result['description']}"
                    )
                    return {"status": "error", "description": "Failed to refresh token"}

                new_short_token = token_result.get("access_token")
                if not new_short_token:
                    logging.error("Failed to retrieve new access token.")
                    return {
                        "status": "error",
                        "description": "Failed to retrieve new access token",
                    }

                # Write the new token to the file
                try:
                    with open(short_token_file, "w") as token_file:
                        token_file.write(new_short_token)
                    logging.info("New short token written to file successfully.")
                except IOError as io_err:
                    logging.error(f"Failed to write new short token to file: {io_err}")
                    return {
                        "status": "error",
                        "description": f"Failed to write new short token: {io_err}",
                    }

                # Increment retries and retry the upload
                retries += 1
                continue  # Retry with the new token

            # Check for success after retry logic
            response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
            logging.info(
                f"File {local_file} uploaded successfully with status code {response.status_code}."
            )

            # Log the successfully uploaded file
            log_uploaded_file(local_file)

            return {
                "status": "success",
                "description": f"File {local_file} uploaded successfully",
            }

        except requests.exceptions.HTTPError as http_err:
            logging.error(
                f"HTTP error occurred during file upload: {http_err} - Status code: {response.status_code}"
            )
            return {"status": "error", "description": f"HTTP error: {http_err}"}

        except requests.exceptions.ConnectionError as conn_err:
            logging.error(f"Connection error occurred during file upload: {conn_err}")
            return {"status": "error", "description": f"Connection error: {conn_err}"}

        except requests.exceptions.Timeout as timeout_err:
            logging.error(f"Timeout error occurred during file upload: {timeout_err}")
            return {"status": "error", "description": f"Timeout error: {timeout_err}"}

        except requests.exceptions.RequestException as req_err:
            logging.error(
                f"An error occurred during the file upload request: {req_err}"
            )
            return {"status": "error", "description": f"Request error: {req_err}"}

        except Exception as e:
            logging.error(f"An unexpected error occurred during file upload: {e}")
            return {"status": "error", "description": f"Unexpected error: {e}"}

    # If we reach this point, it means retries were exhausted
    return {"status": "error", "description": "Failed to upload file after retrying"}
