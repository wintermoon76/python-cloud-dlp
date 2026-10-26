
import os

from azure.storage.blob import BlobServiceClient
from dotenv import load_dotenv

load_dotenv()

CONTAINER_NAMES = [
    "incoming",
    "approved",
    "quarantine",
    "blocked",
]


def get_blob_service_client():
    connection_string = os.getenv(
        "AZURE_STORAGE_CONNECTION_STRING"
    )

    if not connection_string:
        raise ValueError(
            "Azure connection string is missing. "
            "Check your .env file."
        )

    return BlobServiceClient.from_connection_string(
        connection_string
    )


def upload_file(
    file_bytes: bytes,
    filename: str,
    container_name: str,
) -> str:
    if container_name not in CONTAINER_NAMES:
        raise ValueError("Invalid storage container.")

    service = get_blob_service_client()

    blob_client = service.get_blob_client(
        container=container_name,
        blob=filename,
    )

    blob_client.upload_blob(
        file_bytes,
        overwrite=False,
    )

    return blob_client.url


def list_files(container_name: str) -> list[str]:
    if container_name not in CONTAINER_NAMES:
        raise ValueError("Invalid storage container.")

    service = get_blob_service_client()

    container_client = service.get_container_client(
        container_name
    )

    return [
        blob.name
        for blob in container_client.list_blobs()
    ]
