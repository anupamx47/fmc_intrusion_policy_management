import subprocess
import sys

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def main():
    try:
        import requests
    except ImportError:
        print("requests library not found. Installing...")
        install("requests")

    try:
        import tqdm
    except ImportError:
        print("tqdm library not found. Installing...")
        install("tqdm")

    print("All required libraries are installed.")

if __name__ == "__main__":
    main()