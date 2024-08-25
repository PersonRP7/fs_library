from dotenv import load_dotenv
import os
import requests
import json
import logging
import sys
from typing import Union

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


def send_file(
    local_file: str, short_token_file: str, dropbox_dir: str, api_address: str
) -> dict:
    """
    Send a file to Dropbox using the Dropbox API.

    Args:
        local_file (str): The path to the local file to upload.
        short_token_file (str): The path to the file containing the Dropbox short-lived access token.
        dropbox_dir (str): The directory in Dropbox where the file should be uploaded.
        api_address (str): The API endpoint for uploading the file.

    Returns:
        dict: A dictionary indicating the status of the upload and any error messages.
    """
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
        "path": f"{dropbox_dir}/{local_file}",
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
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)

        logging.info(
            f"File {local_file} uploaded successfully with status code {response.status_code}."
        )
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
        logging.error(f"An error occurred during the file upload request: {req_err}")
        return {"status": "error", "description": f"Request error: {req_err}"}

    except Exception as e:
        logging.error(f"An unexpected error occurred during file upload: {e}")
        return {"status": "error", "description": f"Unexpected error: {e}"}


send_file("file5.txt", "short_token.txt", DROPBOX_DIR, API_ADDRESS)

# print(get_new_short_token(API_REFRESH_ADDRESS, REFRESH_TOKEN, APP_KEY, APP_SECRET))
