from dotenv import load_dotenv
import os
import requests
import json
import logging
import sys
from typing import Optional

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


def read_file(file_path: str, mode: str) -> Optional[bytes]:
    """
    Read a file into memory. The `rb` is used when sending the actual
    payload due to Dropbox API specifications.

    Parameters:
        file_path (str): The path to the file to be read.
        mode (str): File open mode. `r` for read, `rb` for read binary.
    Returns:
        Optional[bytes]: The content of the file if successful,
            None if an exception occurs.

    Raises:
        Exception: If any error occurs during file reading.
    """
    try:
        with open(file_path, mode) as f:
            file_content = f.read()
        return file_content
    except Exception as e:
        error_msg = f"Error while reading the file: {file_path} " f"Error: {e}"
        logging.error(error_msg)
        raise


# def send_file(file: str, file_path: str,
#               dropbox_dir_path: str):
#     with open(file_path) as infile:
#         short_token = infile.read()

#     print(short_token)

# print(get_new_short_token(API_REFRESH_ADDRESS, REFRESH_TOKEN, APP_KEY, APP_SECRET))
