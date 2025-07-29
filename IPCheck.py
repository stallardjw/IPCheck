# IPCheck.py
# --------------------------------------------
# IP Reputation Lookup Tool
#
# Checks AbuseIPDB, GreyNoise, and VirusTotal
# for public IP address reputation data.
#
# Author: Jonathan Stallard
# Version: 1.4
# Last Revised: 7/29/2025
# --------------------------------------------
# API Keys are loaded securely from a `.env` file.
# --------------------------------------------

import requests
import os
from dotenv import load_dotenv

# Load API keys from .env file
load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")


def check_abuseipdb(ip):
    """
    Query AbuseIPDB for IP reputation.
    Returns formatted string of results or error.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        abuse_confidence_score = data.get("abuseConfidenceScore", "N/A")
        total_reports = data.get("totalReports", "N/A")
        country = data.get("countryCode", "N/A")
        usage_type = data.get("usageType", "N/A")
        isp = data.get("isp", "N/A")
        return (
            f"AbuseIPDB:\n"
            f"  Abuse Confidence Score: {abuse_confidence_score}\n"
            f"  Total Reports (last 90 days): {total_reports}\n"
            f"  Country: {country}\n"
            f"  Usage Type: {usage_type}\n"
            f"  ISP: {isp}"
        )
    except Exception as e:
        return f"AbuseIPDB – Error: {e}"


def check_greynoise(ip):
    """
    Query the unified GreyNoise v3 API and parse the nested response.
    Returns detailed data if the IP has been observed.
    """
    if not GREYNOISE_API_KEY:
        return "GreyNoise – Error: API key not found. Check your .env file."

    url = f"https://api.greynoise.io/v3/ip/{ip}"
    headers = {
        "Accept": "application/json",
        "key": GREYNOISE_API_KEY
    }
    try:
        resp = requests.get(url, headers=headers, timeout=10)

        if resp.status_code == 404:
            return "GreyNoise – IP not observed."

        resp.raise_for_status()
        data = resp.json()

        # Get the two main data blocks from the response
        isi = data.get("internet_scanner_intelligence", {})
        bsi = data.get("business_service_intelligence", {})

        # Check if GreyNoise found anything in either block
        if not isi.get("found") and not bsi.get("found"):
            return "GreyNoise – IP observed, but no specific intelligence found."

        # Build the report
        lines = ["GreyNoise:"]
        
        if bsi.get("found"):
            lines.append(f"  Name: {bsi.get('name', 'N/A')}")
            lines.append(f"  Category: {bsi.get('category', 'N/A')}")
            description = bsi.get('description')
            if description:
                 lines.append(f"  Description: {description}")

        elif isi.get("found"):
            lines.append(f"  Classification: {isi.get('classification', 'N/A')}")
            lines.append(f"  Last Seen: {isi.get('last_seen', 'N/A')}")
            lines.append(f"  Actor: {isi.get('actor', 'N/A')}")
            if isi.get('tags'):
                tag_names = [tag['name'] for tag in isi['tags']]
                lines.append(f"  Tags: {', '.join(tag_names)}")

        return "\n".join(lines)

    except requests.exceptions.HTTPError as http_err:
        try:
            error_message = http_err.response.json().get("message", http_err)
        except Exception:
            error_message = http_err
        return f"GreyNoise – Error: {error_message}"
    except Exception as e:
        return f"GreyNoise – Error: {e}"


def check_virustotal(ip):
    """
    Query VirusTotal v3 API for reputation on the IP.
    Returns basic detection stats from multiple engines.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 404:
            return "VirusTotal – No data for IP."
        resp.raise_for_status()
        data = resp.json()
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        harmless = last_analysis_stats.get("harmless", 0)
        undetected = last_analysis_stats.get("undetected", 0)
        return (
            f"VirusTotal:\n"
            f"  Malicious detections: {malicious}\n"
            f"  Suspicious detections: {suspicious}\n"
            f"  Harmless detections: {harmless}\n"
            f"  Undetected: {undetected}"
        )
    except Exception as e:
        return f"VirusTotal – Error: {e}"


def main():
    """
    Prompt for IP address and run reputation checks.
    Exits on 'exit' or Ctrl+C.
    """
    print("🔍 IP Reputation Checker")
    print("Type 'exit' or press Ctrl+C to quit.\n")

    while True:
        ip = input("Enter IP address to check: ").strip()
        if ip.lower() == "exit":
            print("Exiting")
            break
        print("\n--- Reputation Report ---\n")
        print(check_abuseipdb(ip))
        print()
        print(check_greynoise(ip))
        print()
        print(check_virustotal(ip))
        print("\n------------------------\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting")