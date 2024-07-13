import requests
import csv
from getpass import getpass
from tqdm import tqdm
from datetime import datetime

# Script Metadata
__author__ = "Anupam Pavithran (anpavith@cisco.com)"
__version__ = "1.0.0"

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class FMC:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.headers, self.domain_id = self.get_auth_headers_and_domain()

    def get_auth_headers_and_domain(self):
        url = f"https://{self.host}/api/fmc_platform/v1/auth/generatetoken"
        response = requests.post(url, auth=(self.username, self.password), verify=False)
        response.raise_for_status()
        auth_headers = {
            'X-auth-access-token': response.headers['X-auth-access-token'],
            'Content-Type': 'application/json'
        }
        domain_id = response.headers['DOMAIN_UUID']
        return auth_headers, domain_id

    def get_intrusion_policies(self):
        url = f"https://{self.host}/api/fmc_config/v1/domain/{self.domain_id}/policy/intrusionpolicies"
        response = requests.get(url, headers=self.headers, verify=False)
        response.raise_for_status()
        return response.json()['items']

    def get_intrusion_policy_rules(self, policy_id):
        rules = []
        offset = 0
        limit = 5000
        total_rules = self.get_total_rules(policy_id)

        with tqdm(total=total_rules, desc="Fetching Rules", unit="rule") as pbar:
            while True:
                url = f"https://{self.host}/api/fmc_config/v1/domain/{self.domain_id}/policy/intrusionpolicies/{policy_id}/intrusionrules?offset={offset}&limit={limit}&expanded=true"
                response = requests.get(url, headers=self.headers, verify=False)
                response.raise_for_status()
                data = response.json()
                rules.extend(data['items'])
                pbar.update(len(data['items']))
                if len(data['items']) < limit:
                    break
                offset += limit

        return rules

    def get_total_rules(self, policy_id):
        url = f"https://{self.host}/api/fmc_config/v1/domain/{self.domain_id}/policy/intrusionpolicies/{policy_id}/intrusionrules?offset=0&limit=1&expanded=true"
        response = requests.get(url, headers=self.headers, verify=False)
        response.raise_for_status()
        data = response.json()
        return data['paging']['count']

def write_rules_to_csv(policy_name, rules):
    current_datetime = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{policy_name.replace(' ', '_')}_rules_{current_datetime}.csv"
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Rule ID", "Name", "Default State", "Message", "Rule Data"])
        for rule in rules:
            writer.writerow([rule['id'], rule['name'], rule.get('defaultState', 'N/A'), rule['msg'], rule['ruleData']])
    print(f"Rules have been written to {filename}")

def main():
    print(f"Script Version: {__version__}")
    print(f"Author: {__author__}")
    
    host = input("Enter FMC host: ")
    username = input("Enter FMC username: ")
    password = getpass("Enter FMC password: ")

    fmc = FMC(host, username, password)

    print("Fetching Intrusion Policies...")
    intrusion_policies = fmc.get_intrusion_policies()

    if not intrusion_policies:
        print("No intrusion policies found.")
        return

    while True:
        for idx, policy in enumerate(intrusion_policies):
            print(f"{idx + 1}: {policy['name']} (ID: {policy['id']})")

        try:
            policy_idx = int(input("Select an Intrusion Policy by number: ")) - 1

            if 0 <= policy_idx < len(intrusion_policies):
                selected_policy = intrusion_policies[policy_idx]
                break
            else:
                print("Invalid selection. Please select a valid number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    print(f"Fetching rules for Intrusion Policy: {selected_policy['name']}")

    rules = fmc.get_intrusion_policy_rules(selected_policy['id'])

    if not rules:
        print("No rules found for the selected intrusion policy.")
        return

    write_rules_to_csv(selected_policy['name'], rules)

if __name__ == "__main__":
    main()