# Phishdomain_Slack

Catching malicious phishing domain names using [certstream](https://certstream.calidog.io/) SSL certificates live stream.

This script is alerting through slack, if any phishing domains found related to your organization. if you want to track all suspicious domains in splunk, please monitor suspicious_domains.log file. 


### Installation

The script should work fine using Python2 or Python3.

You will need the following python packages installed: certstream, tqdm, entropy, termcolor, tld, python_Levenshtein,slackclient

```sh
pip install -r requirements.txt
```

### Usage
```
$ Open ./domains.py script and modify based on your organization. Ex: google 
```

```
$ Open ./catch_phish.py script and put Your Slack Oauth Token and Channel ID.
```
```
$ Open ./catch_phish.py script go to l=[] #Put same keywords which is put it in domains.py
```

```
$ ./catch_phish.py
```
