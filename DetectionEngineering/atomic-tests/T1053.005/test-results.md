# Atomic Red Team Test Results — T1053.005

## Objective

Validate the Sigma detection rule for scheduled task creation using controlled Atomic Red Team testing.

## MITRE ATT&CK

* Technique ID: T1053.005
* Technique: Scheduled Task/Job — Scheduled Task

## Test Details

* Tool: Atomic Red Team
* Atomic Test Number: 14
* Test Name: Turla KopiLuwak Scheduled Task for JavaScript Stager
* Test task name: ProactiveScan

## Telemetry

* Source: Windows Sysmon
* Event ID: 1 — Process Creation
* Evidence: Sysmon.evtx
* Log location: `C:\DetectionEngineering\logs\T1053.005_Scheduled_Task\Sysmon.evtx`

## Detection

* Detection tool: Chainsaw
* Rule: `T1053.005_scheduled_task.yml`
* Rule title: Scheduled Task Created Using Schtasks
* Result: One matching detection reported when hunting with this rule.
* Verification: The Sysmon event shows `schtasks.exe` with the `/create` argument and the task name `ProactiveScan`.

## Conclusion

The controlled test generated the expected scheduled-task creation behavior, and the Sigma rule produced a matching detection in the collected Sysmon evidence.

## Next Steps

Test legitimate scheduled-task creation to evaluate potential false positives, document the results, and tune the rule if necessary.
