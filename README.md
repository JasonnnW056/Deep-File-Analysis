# Deep File Analysis
 
A Flask web app that checks a file for warning signs before you open it. It has two scan modes:
 
- **Fast scan** reads the file without running it (static analysis). Takes seconds.
- **Hybrid scan** does the fast scan, then runs the file in a [CAPEv2](https://github.com/kevoreilly/CAPEv2) sandbox and watches what it does. Takes minutes.
Both modes end in one report with a risk level, the evidence behind it, and a downloadable PDF. Past scans are kept in a History page.
 
> **Warning:** Hybrid mode executes the file you upload. Only use it with a properly isolated CAPE setup (see [Safety](#safety)).
 
## Features
 
- Static analysis: real file type, hashes, entropy, URLs and IPs in the file, PE headers and imports, PDF and Office checks, YARA rules, optional VirusTotal lookup
- Sandbox analysis through CAPE: behavior signatures, MITRE ATT&CK techniques, commands run, files and registry changes, network activity, dropped files, extracted payloads, known malware family matches
- One combined verdict: the higher of the static and sandbox results
- PDF report for every scan, with static and sandbox sections
- Scan history stored in Supabase, so reports can be reopened
- Plain-language homepage that explains both modes for non-technical users
- Hybrid scans accept a fixed list of supported file types; fast scans accept any file up to 50 MB

## How it works
 
```
upload -> temp folder -> static scan (scan_file)
                      -> hybrid only: CAPE submit -> poll status -> fetch report
                      -> normalize report -> verdict -> PDF report
                      -> temp folder deleted -> result page + history
```
 
**Risk level.** Static analysis gives `none`, `low`, `medium` or `high`. The sandbox verdict is built from the CAPE score (out of 10), plus extra weight for a known malware family match and for each high-severity behavior signature. A result of `MALWARE` counts as `high`. The final risk is the higher of the two, so a quiet sandbox run cannot hide a bad static result, and the other way round. A clean result never proves a file is safe.
 
 ## Requirements
 
- Python 3.12 (3.10 or newer should work)
- A running CAPEv2 server with its REST API enabled (`/apiv2`) and at least one Windows guest, for hybrid scans
- A Supabase project for scan history (optional; the app keeps working if it is unavailable)
- Python packages: Flask, requests, reportlab, plus the static analysis libraries listed in `requirements.txt`

## Getting Started

### 1. Clone the Repository and Move to the Folder
```bash
git clone https://github.com/JasonnnW056/Deep-File-Analysis.git
cd Deep-File-Analysis
```

### 2. Create a Virtual Environment and Install the libraries 
Windows:
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```
### 3. Run the application
Run the main.py
```bash
python main.py
```
## Using it
 
1. Open the homepage and choose **Start scanning**.
2. Pick a file and a mode (Hybrid is the default).
3. Read the result page: the header shows the final risk, with the static and sandbox results listed separately.
4. Use **Download PDF report** to keep a copy. PDFs live in a temporary folder and are removed when the app exits.
5. Open **History** to reopen earlier scans.
If the sandbox is offline, times out or fails, the scan falls back to static results only and the page says so.

## Supported file types
 
Fast scans read any file up to 50 MB. Hybrid scans are limited to the types in `FILE_GROUPS` in `app/web/routes.py`: Windows programs, scripts, Office and PDF documents, email files, archives, shortcuts and settings files, and Java and Flash files. Edit that list to change what the upload page, the file picker and the server check all accept.
 
Office, PDF and Java samples only run properly if the CAPE guest has the matching software installed. Linux files (ELF, shell scripts) cannot run unless you add a Linux guest.

## Safety
 
Hybrid mode runs real malware if you give it real malware. Before using it:
 
- Keep the CAPE guest on an isolated network (no route to the internet, or an INetSim style fake internet). Test this from inside the guest, then revert the snapshot.
- Make sure CAPE reverts the guest snapshot after every run, and keep personal accounts and saved passwords out of the guest image.
- Run the Flask app on a machine you can afford to treat as exposed. Do not install Wine on it. Uploaded files are saved, scanned and deleted, never executed on the web host.
- Download test samples on the analysis host or a throwaway VM, never your everyday machine.
- Do not click domains or IP addresses shown in a report. They are real addresses the sample contacted.
- Do not upload files that contain private information. Report details (file name, hashes, findings) are saved in History, and the sandbox keeps its own record of each run.