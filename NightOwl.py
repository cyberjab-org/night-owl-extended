import email
from email import policy
from genericpath import exists
import sys
import os
import re
from typing import Final
import colorama
import extract_msg
from colorama import Fore
colorama.init(autoreset=True)

global count

def fileChecker(file, data):
    if file.endswith('.msg'):
        print("msg format is not supported")
    elif file.endswith('.eml'):
        data = baseGrabber(file, data)
    else:
        print(Fore.RED + "The file is in " + file.split(".")[-1] + " format: " + file)
    return data

def baseGrabber(file, data):
    data['base'] = {}
    try:
        count = 0
        with open(file, "r", encoding="utf-8") as sample:
            for line in sample:
                if line.startswith("From: "):
                    data['base']["from"] = line.strip()
                if line.startswith("To: "):
                    data['base']["to"] = line.strip()
                if line.startswith("Subject: "):
                    data['base']["subject"] = line.strip()
                if line.startswith("Date: "):
                    data['base']["date"] = line.strip()
                if line.startswith("Message-ID: "):
                    data['base']["message-id"] = line.strip()
                if line.startswith("Return-Path:"):
                    data['base']["return-path"] = line.strip()
                if line.startswith("Return-To:"):
                    data['base']["return-to"] = line.strip()
                if line.startswith("List-Unsubscribe:"):
                    data['base']["list-unsubscribe"] = line.strip()
                if line.startswith("Message Body: "):
                    data['base']["message-body"] = line.strip()
                if line.startswith("Received: "):
                    count += 1

        data['base']["total-hops"] = count

    except Exception:
        print("Something Went Wrong in Base Grabber!")
        exit

    finally:
        data = emailGrabber(file, data)
    return data

def emailGrabber(file, data):

    try:
        fileOpen = open(file,'r', encoding='utf-8')
        readText = fileOpen.read()
        EMAIL = []
        regex = re.findall(r'[\w\.-]+@[\w\.-]+', readText)
        if regex is not None:
            for match in regex:
                if match not in EMAIL:
                    EMAIL.append(match)

        data["emails"] = EMAIL
    except:
        print("Something Went Wrong in Email Grabber!")
        exit

    finally:
        data = ipGrabber(file, data)
    return data


def ipGrabber(file, data):

    try:
        fileOpen = open(file,'r', encoding='utf-8')
        readText = fileOpen.read()
        IP = []
        IP_COUNT = 0
        regex = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',readText)
        if regex is not None:
            for match in regex:
                if match not in IP:
                    IP.append(match)
                    IP_COUNT += 1
        data["ip_addresses"] = IP

    except:
        print("Something Went Wrong IP Grabber!")
        exit

    finally:
        data = urlGrabber(file, data)
    return data


def urlGrabber(file, data):
    # try:
    fileOpen = open(file,'r', encoding='utf-8')
    readText = fileOpen.read()
    urls = re.search("(?P<url>https?://[^\s]+)", readText)

    if urls:
        data['urls_group'] = urls.group("url")

    URL = []
    regex = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]',readText)

    try:
        if regex is not None:
                for match in regex:
                    if match not in URL:
                        URL.append(match)
        data['urls'] = URL

    except:
        print("Something Went Wrong In URL Grabber")

    finally:
        data = xHunter(file, data)


    return data


def xHunter(file, data):
    data['headers'] = {}
    try:
        with open(file,'r', encoding='utf-8') as sample:
                for line in sample:
                    if line.startswith("X-"):
                        header_key = line[:line.find(": ")]
                        data['headers'][header_key] = str(line[line.find(": ") + 1:]).strip()
    except:
        print("No X Headers Observed")

    finally:
        data = embedAttachments(file, data)
    return data

def embedAttachments(file, data):
    data['attachments'] = []

    emailFNameF = "Attachments"
    c_path = os.getcwd()
    exportedPath = os.path.join(c_path, emailFNameF)

    try:
        with open(file, "r") as f:
            attachFile = email.message_from_file(f, policy=policy.default)
            for attachment in attachFile.iter_attachments():
                    attName = attachment.get_filename()
                    data['attachments'].append(attName)
                    with open(os.path.join(exportedPath, attName), "wb") as fileWrite:
                            fileWrite.write(attachment.get_payload(decode=True))

    except:
        print("Something Went Wrong In Embed Attachments")

    return data


def main():
    file = "mail.eml"
    data = {}
    return fileChecker(file, data)
if __name__ == "__main__":
    main()
