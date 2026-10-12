# Atomic Red Team Test Results — T1059.001

## Objective

Validate detection of encoded PowerShell execution using controlled testing and Sysmon telemetry.

## MITRE ATT&CK

* Technique ID: T1059.001
* Technique: Command and Scripting Interpreter — PowerShell

## Detection Rule

* Rule: `T1059.001_encoded_powershell.yml`
* Title: PowerShell Launched With Encoded Command
* Detection tool: Chainsaw

## Evidence

* Log source: Windows Sysmon
* Event ID: 1 — Process Creation
* Evidence file: `logs/T1059.001_Encoded_PowerShell/Sysmon.evtx`

## Test Results

* The Sigma rule was validated successfully.
* Chainsaw reported two detections across two documents during the hunt.
* One recorded match was a PowerShell process launched with encoded-command indicators.
* A benign `Get-Process` command was tested and did not satisfy the encoded-command detection conditions.

## Conclusion

The collected evidence contained activity matching the encoded-PowerShell detection rule. The tested benign command did not match the rule's detection conditions.

The benign test was limited to this specific command and does not establish the overall false-positive rate.

## Limitations

Additional benign PowerShell activities and repeatable test scenarios would be needed to evaluate detection coverage and false positives more broadly.
