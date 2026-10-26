
from dlp.cloud_storage import get_blob_service_client


def main():
    service = get_blob_service_client()

    service.get_account_information()

    print("Azure Blob Storage connection successful!")


if __name__ == "__main__":
    main()
