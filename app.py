import PySimpleGUI as sg
import boto3
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError, ServiceResponseError
import paramiko
from google.cloud import bigquery
from google.auth import exceptions
from google.auth.transport.requests import Request
from google.auth.credentials import Credentials
import json


def check_s3_credentials(access_key_id, secret_access_key, result_elem):
    try:
        # Create an S3 client
        s3 = boto3.client(
            's3',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key
        )

        # Attempt to list buckets to check credentials
        response = s3.list_buckets()

        # If no exception is raised, credentials are valid
        result_elem.update('AWS S3 - Credentials are valid. Connection successful!', text_color='green')

    except Exception as e:
        # Credentials are invalid or there was an error
        result_elem.update('AWS S3 - Credentials are invalid or there was an error: {}'.format(e), text_color='red')


def check_azure_blob_credentials(account_name, account_key, result_elem):
    try:
        if account_key.startswith('sp='):
            # If account_key starts with 'sp=', treat it as a SAS key
            sas_key = account_key
            blob_service_client = BlobServiceClient.from_connection_string(
                f"https://{account_name}.blob.core.windows.net?{sas_key}")
        else:
            blob_service_client = BlobServiceClient(account_url=f"https://{account_name}.blob.core.windows.net",
                                                    credential=account_key)

        containers = blob_service_client.list_containers()
        container_list = "\n".join(container['name'] for container in containers)
        result_elem.update(f"Azure Blob - Credentials are valid. List of containers:\n{container_list}",
                           text_color='green')

    except ResourceNotFoundError as e:
        result_elem.update(f"Resource not found: {e}", text_color='red')
    except ServiceResponseError as e:
        result_elem.update(f"Service response error: {e}", text_color='red')
    except Exception as e:
        result_elem.update(f"An error occurred: {e}", text_color='red')


def check_sftp_credentials(hostname, port, username, private_key_path, result_elem):
    try:
        transport = paramiko.Transport((hostname, port))
        private_key = paramiko.RSAKey(filename=private_key_path)
        transport.connect(username=username, pkey=private_key)
        transport.close()
        result_elem.update('SFTP - Credentials are valid, key-based authentication successful!', text_color='green')

    except paramiko.AuthenticationException:
        result_elem.update('SFTP - Authentication failed. Key-based authentication unsuccessful.', text_color='red')
    except paramiko.SSHException as e:
        result_elem.update(f"Unable to establish SSH connection: {e}", text_color='red')
    except Exception as e:
        result_elem.update(f"An error occurred: {e}", text_color='red')


def check_bigquery_credentials(project_id, dataset_name, google_application_credentials, result_elem):
    try:
        from google.oauth2 import service_account

        # Load credentials from the provided JSON file
        credentials = service_account.Credentials.from_service_account_file(google_application_credentials)

        # Create a BigQuery client with the loaded credentials
        client = bigquery.Client(project=project_id, credentials=credentials)

        # List datasets to check if credentials are valid
        datasets = list(client.list_datasets())

        if datasets:
            dataset_list = "\n".join(dataset.dataset_id for dataset in datasets)
            result_elem.update(f"BigQuery - Credentials are valid. List of datasets:\n{dataset_list}",
                               text_color='green')
        else:
            result_elem.update("BigQuery - No datasets found. Check your credentials and permissions.",
                               text_color='red')

    except Exception as e:
        result_elem.update(f"An error occurred: {e}", text_color='red')




sg.theme('Black')

layout = [
    [sg.Button('AWS S3'), sg.Button('Azure Blob'), sg.Button('SFTP'), sg.Button('BigQuery')],
    [sg.Text('', size=(40, 2), key='-RESULT-', text_color='white')]  # Text element for displaying result
]

window = sg.Window('Credential Checker', layout)

while True:
    event, values = window.read()

    if event == sg.WINDOW_CLOSED:
        break

    if event == 'AWS S3':
        layout_aws = [
            [sg.Text('Enter AWS Access Key:'), sg.InputText(key='-ACCESS-')],
            [sg.Text('Enter AWS Secret Key:'), sg.InputText(key='-SECRET-', password_char='*')],
            [sg.Button('Check Credentials'), sg.Button('Exit')],
            [sg.Text('', size=(40, 2), key='-RESULT-AWS-', text_color='white')]
            # Text element for displaying result in AWS S3 window
        ]

        window_aws = sg.Window('AWS S3 Credentials Checker', layout_aws)

        while True:
            event_aws, values_aws = window_aws.read()

            if event_aws == sg.WINDOW_CLOSED or event_aws == 'Exit':
                window_aws.close()
                break

            if event_aws == 'Check Credentials':
                access_key = values_aws['-ACCESS-']
                secret_key = values_aws['-SECRET-']

                check_s3_credentials(access_key, secret_key, window_aws['-RESULT-AWS-'])

    elif event == 'Azure Blob':
        layout_azure = [
            [sg.Text('Azure Blob Storage Account Name:'), sg.InputText(key='account_name')],
            [sg.Text('Account Key or SAS Key:'), sg.InputText(key='account_key')],
            [sg.Button('Check Credentials'), sg.Button('Exit')],
            [sg.Text('', size=(40, 2), key='-RESULT-AZURE-', text_color='white')]
            # Text element for displaying result in Azure Blob window
        ]

        window_azure = sg.Window('Azure Blob Storage Credentials Checker', layout_azure)

        while True:
            event_azure, values_azure = window_azure.read()

            if event_azure == sg.WINDOW_CLOSED or event_azure == 'Exit':
                window_azure.close()
                break
            elif event_azure == 'Check Credentials':
                account_name = values_azure['account_name']
                account_key = values_azure['account_key']

                check_azure_blob_credentials(account_name, account_key, window_azure['-RESULT-AZURE-'])

    elif event == 'SFTP':
        layout_sftp = [
            [sg.Text("Hostname"), sg.InputText(key="hostname")],
            [sg.Text("Port"), sg.Input(default_text="22", key="port", size=(5, 1), enable_events=True)],
            [sg.Text("Username"), sg.InputText(key="username")],
            [sg.Text("Private Key Path"), sg.InputText(key="private_key_path"), sg.FileBrowse()],
            [sg.Button("Check Credentials", bind_return_key=True), sg.Button('Exit')],
            [sg.Text('', size=(40, 2), key='-RESULT-SFTP-', text_color='white')]
            # Text element for displaying result in SFTP window
        ]

        window_sftp = sg.Window("SFTP Credentials Checker", layout_sftp, return_keyboard_events=True,
                                background_color='black')

        while True:
            event_sftp, values_sftp = window_sftp.read()

            if event_sftp == sg.WINDOW_CLOSED or event_sftp == 'Exit':
                window_sftp.close()
                break
            elif event_sftp == 'port':
                # Filter non-integer characters while typing
                window_sftp['port'].update(''.join(filter(str.isdigit, values_sftp['port'])))

            elif event_sftp == "Check Credentials" or event_sftp == ' ':
                hostname = values_sftp["hostname"]
                port = int(values_sftp["port"])
                username = values_sftp["username"]
                private_key_path = values_sftp["private_key_path"]

                check_sftp_credentials(hostname, port, username, private_key_path, window_sftp['-RESULT-SFTP-'])

    elif event == 'BigQuery':
        layout_bigquery = [
            [sg.Text('BigQuery Project ID:'), sg.InputText(key='project_id')],
            [sg.Text('BigQuery Dataset Name:'), sg.InputText(key='dataset_name')],
            [sg.Text('Google Application Credentials (JSON):'), sg.InputText(key='google_application_credentials'),
             sg.FileBrowse()],
            [sg.Button('Check Credentials'), sg.Button('Exit')],
            [sg.Text('', size=(80, 2), key='-RESULT-BIGQUERY-', text_color='white')]
            # Text element for displaying result in BigQuery window
        ]

        window_bigquery = sg.Window('BigQuery Credentials Checker', layout_bigquery)

        while True:
            event_bigquery, values_bigquery = window_bigquery.read()

            if event_bigquery == sg.WINDOW_CLOSED or event_bigquery == 'Exit':
                window_bigquery.close()
                break
            elif event_bigquery == 'Check Credentials':
                project_id = values_bigquery['project_id']
                dataset_name = values_bigquery['dataset_name']
                google_application_credentials = values_bigquery['google_application_credentials']

                check_bigquery_credentials(project_id, dataset_name, google_application_credentials,
                                           window_bigquery['-RESULT-BIGQUERY-'])

window.close()
