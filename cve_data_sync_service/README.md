# CVE Data Sync Service

**CVE DataSync** is a service designed to periodically fetch, update, and store the latest CVE (Common Vulnerabilities and Exposures) data from the official CVE repository. It ensures that your local data is always up-to-date, providing a reliable source of information for security analysis and reporting.

## Features

- **Periodic Data Fetching**: Automatically pulls the latest CVE data from the GitHub repository every 6 hours.
- **Data Storage**: Stores the fetched data locally in a JSON file or database for easy access.
- **Scalability**: Designed to be run as an independent service, making it easy to scale and integrate with other systems.
- **Simple Setup**: Easily configurable and deployable using basic Python dependencies.

## Getting Started

### Prerequisites

Ensure you have Python 3.12+ installed on your system. You'll also need to install the necessary Python packages:

```bash
pip install -r requirements.txt
```
### Usage
To start the CVE DataSync service, simply run the following command:


```bash
python main.py
```

By default, the service will:

- Clone the latest CVE data from the official GitHub repository if it doesn't already exist locally.
- Pull updates every 6 hours to ensure the local data is up-to-date.

You can adjust the fetch interval by modifying the time.sleep() value in the `cve_data_sync.py` script.

Configuration
You can customize the service by modifying the following parameters in the cve_data_sync.py script:

* Repository URL: The GitHub URL from which CVE data is fetched.
* Fetch Interval: The interval in hours between each data fetch (default is 6 hours).
* Data Storage: Path to where the fetched data will be stored.
