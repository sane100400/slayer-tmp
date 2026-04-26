import subprocess

def run_report(report_name: str):
    # shell=False but argument still built from user input — still injectable via arg splitting
    cmd = "generate-report " + report_name
    return subprocess.run(cmd.split(), shell=False, capture_output=True)
