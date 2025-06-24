# IPCheck.py
# --------------------------------------------
# IP Reputation Lookup Tool
#
# Checks AbuseIPDB, GreyNoise, and VirusTotal
# for public IP address reputation data.
#
# Author: Jonathan Stallard
# Version: 1.2
# Last Revised: 6/24/2025
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
    Query GreyNoise Community API.
    Returns classification and metadata if available.
    """
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {
        "Accept": "application/json",
        "key": GREYNOISE_API_KEY
    }
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 404:
            return f"GreyNoise – No data for IP."
        resp.raise_for_status()
        data = resp.json()
        classification = data.get("classification", "N/A")
        name = data.get("name", "N/A")
        message = data.get("message", "")
        return (
            f"GreyNoise Community:\n"
            f"  Classification: {classification}\n"
            f"  Name: {name}\n"
            f"  Message: {message}"
        )
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
