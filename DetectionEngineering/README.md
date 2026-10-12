# Detection Engineering Repository

## 1. Project Overview

This project focuses on developing, testing, and improving security detection rules using Sigma, MITRE ATT&CK, Sysmon, Atomic Red Team, and Chainsaw.

The objective is to determine whether detection rules identify specific attack-like behaviors and evaluate whether legitimate activity also triggers alerts. The project includes controlled testing, false-positive analysis, and rule tuning.

## 2. Project Objectives

* Develop behavior-specific Sigma detection rules.
* Map detection rules to MITRE ATT&CK techniques.
* Generate controlled test activity using Atomic Red Team.
* Collect Windows telemetry using Sysmon.
* Validate detections against exported EVTX logs using Chainsaw.
* Test benign activity to identify potential false positives.
* Tune and retest detection rules based on observed results.
* Document evidence, findings, and limitations in a structured repository.

## 3. Tools Used

| Tool                              | Purpose                                                      |
| --------------------------------- | ------------------------------------------------------------ |
| Sysmon                            | Collects detailed Windows system activity                    |
| Atomic Red Team                   | Generates controlled, repeatable ATT&CK-mapped test activity |
| Sigma                             | Defines detection rules in a portable rule format            |
| Chainsaw                          | Hunts through EVTX logs using Sigma rules                    |
| MITRE ATT&CK                      | Provides a framework for classifying adversary techniques    |
| Windows Event Viewer / PowerShell | Helps inspect and export Windows event logs                  |

## 4. Detection Workflow

1. Select a behavior and identify its MITRE ATT&CK technique.
2. Create a Sigma detection rule for the behavior.
3. Generate controlled test activity using Atomic Red Team.
4. Collect the resulting telemetry with Sysmon.
5. Export the logs into EVTX files.
6. Apply Sigma rules to the logs using Chainsaw.
7. Test legitimate activity and review potential false positives.
8. Tune the rule where appropriate and retest it.
9. Document the results and supporting evidence.

## 5. Use Case 1: Encoded PowerShell

**MITRE ATT&CK:** T1059.001 — PowerShell

**Objective:** Detect PowerShell processes launched with encoded-command arguments.

**Detection rule:** `sigma/T1059.001_encoded_powershell.yml`

**Evidence:** `logs/T1059.001_Encoded_PowerShell/Sysmon.evtx`

**Testing and results:**

* A Sigma rule was created to identify PowerShell processes with encoded-command indicators.
* Chainsaw successfully matched the rule against Sysmon evidence.
* A benign `Get-Process` command was tested.
* The tested benign command did not satisfy the encoded-command detection conditions.

**Limitation:** The benign test was limited to the specific command tested. Additional legitimate PowerShell scenarios would be needed to evaluate false-positive behavior more broadly.

## 6. Use Case 2: Scheduled Task Creation

**MITRE ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task

**Objective:** Detect scheduled-task creation and evaluate whether a more specific rule can distinguish the selected test behavior from the tested benign activity.

**Original rule:** `sigma/T1053.005_scheduled_task.yml`

**Tuned rule:** `sigma/T1053.005_scheduled_task_tuned.yml`

**Atomic test:** T1053.005, Atomic Test #14, which created the task `ProactiveScan`.

**Evidence:**

* `logs/T1053.005_Scheduled_Task/Sysmon.evtx`
* `logs/T1053.005_Scheduled_Task/Sysmon_BenignTest.evtx`
* `logs/T1053.005_Scheduled_Task/Sysmon_BenignOnly.evtx`

### Original detection rule

The original rule identifies `schtasks.exe` commands containing `/create`.

This rule detected the scheduled-task test but also matched the repeated creation attempts for the benign task `BenignDetectionTest`.

### Rule tuning

The tuned rule requires the command line to contain `/create`, `/sc onlogon`, and `wscript.exe`.

The rule was tested against both the Atomic Red Team evidence and the isolated benign-task evidence.

### Comparative results

| Test scenario                  | Original rule      | Tuned rule   |
| ------------------------------ | ------------------ | ------------ |
| Selected Atomic Red Team test  | Detection observed | 1 detection  |
| Benign scheduled-task creation | 3 detections       | 0 detections |

The results indicate that the tuned rule was more selective in these specific test scenarios while retaining detection of the selected Atomic test.

These observations do not establish that the tuned rule will detect every suspicious scheduled task or avoid all false positives.

## 7. Repository Structure

* `sigma/` — Original and tuned Sigma rules.
* `logs/` — Exported Sysmon EVTX evidence.
* `atomic-tests/` — Atomic test details and test results.
* `false-positives/` — Benign-test observations and rule-tuning analysis.
* `results/` — Detection outputs and comparative findings.

## 8. Research Limitations

* Only two ATT&CK use cases were evaluated.
* Testing was performed in a controlled Windows virtual machine.
* The findings apply to the specific test scenarios and logs examined.
* Benign testing was limited and does not represent every legitimate administrative behavior.
* A matching detection indicates that the rule's conditions were met; it does not independently prove malicious intent.
* Further testing would be needed to evaluate broader detection coverage and false-positive behavior.

## 9. Conclusion

This project demonstrates a repeatable workflow for creating and validating Sigma detections using ATT&CK-mapped test scenarios, Sysmon telemetry, and Chainsaw.

The scheduled-task use case also demonstrates how benign testing can reveal broad detection conditions and guide rule tuning. The results provide a starting point for further detection engineering and validation.
