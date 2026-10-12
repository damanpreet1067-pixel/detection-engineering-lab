# Detection Results and Comparative Analysis

## 1. Project Summary

This project evaluates two ATT&CK-mapped detection use cases using Sigma rules, Sysmon telemetry, Atomic Red Team, and Chainsaw.

The aim is to verify detection behavior, test selected benign activity, document potential false positives, and assess whether rule tuning improves selectivity.

## 2. Use Case 1: Encoded PowerShell

* **MITRE ATT&CK:** T1059.001 — PowerShell
* **Sigma rule:** `T1059.001_encoded_powershell.yml`
* **Evidence:** `logs/T1059.001_Encoded_PowerShell/Sysmon.evtx`
* **Detection tool:** Chainsaw

### Results

The Sigma rule was validated, and Chainsaw reported matching detections in the collected Sysmon evidence. A benign `Get-Process` command was also tested and did not satisfy the encoded-command detection conditions.

### Conclusion

The rule detected the targeted encoded-PowerShell behavior in the collected evidence. The benign test was limited to the specific command examined and does not establish the rule's overall false-positive rate.

## 3. Use Case 2: Scheduled Task Creation

* **MITRE ATT&CK:** T1053.005 — Scheduled Task
* **Atomic Red Team test:** Test #14
* **Simulated task:** `ProactiveScan`
* **Original rule:** `T1053.005_scheduled_task.yml`
* **Tuned rule:** `T1053.005_scheduled_task_tuned.yml`

### Test Evidence

The original Sysmon evidence contained the `schtasks.exe` process-creation event associated with creating `ProactiveScan`. Chainsaw reported one detection when the original rule was tested against this evidence. The tuned rule also reported one detection against the same Atomic test evidence.

### Benign Activity

A harmless task named `BenignDetectionTest` was created using `schtasks.exe`, with an action of `cmd.exe /c exit 0`.

The isolated benign evidence contained three process-creation events associated with repeated task-creation attempts.

### Comparative Results

| Test scenario                 | Original rule | Tuned rule   |
| ----------------------------- | ------------- | ------------ |
| Selected Atomic Red Team test | 1 detection   | 1 detection  |
| Isolated benign-task evidence | 3 detections  | 0 detections |

### Analysis

The original rule detects scheduled-task creation broadly by checking for `schtasks.exe` and `/create`. Consequently, it also matched the tested legitimate task-creation events.

The tuned rule additionally requires `/sc onlogon` and `wscript.exe`. In the scenarios tested, it retained detection of the selected Atomic Red Team behavior and did not detect the isolated benign task.

### Conclusion

The tuned rule was more selective in these specific test scenarios. Further evaluation is needed to determine whether it detects other suspicious scheduled-task behaviors and how it performs against a broader range of legitimate activity.

## 4. Overall Findings

1. Sigma rules were created and validated for two ATT&CK techniques.
2. Sysmon logs provided process-creation evidence for the tested behaviors.
3. Chainsaw was used to apply Sigma rules to exported EVTX files.
4. Benign testing exposed the broad matching conditions of the original scheduled-task rule.
5. Tuning reduced matches on the tested benign evidence while preserving detection of the selected Atomic test.

## 5. Limitations

* The project evaluates only two use cases.
* Benign testing covers only the specific activities recorded.
* Detection counts apply to the evidence files and scenarios tested.
* A rule match alone does not establish malicious intent.
* Additional test cases are required to evaluate detection coverage and false-positive behavior more broadly.
