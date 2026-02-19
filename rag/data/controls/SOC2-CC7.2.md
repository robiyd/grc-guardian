# SOC 2 CC7.2: System Monitoring

## Control ID
CC7.2

## Framework
SOC 2 (Trust Services Criteria)

## Control Family
Common Criteria - System Operations

## Control Summary
The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives; anomalies are analyzed to determine whether they represent security events. This includes:
- Designing and deploying detection mechanisms
- Implementing filters to analyze events
- Monitoring infrastructure and software
- Defining alerts for notification of management

## What GRC Guardian Checks

### AWS Config Rules Mapped
- `cloudtrail-enabled` - Activity monitoring via CloudTrail
- `guardduty-enabled-centralized` - Threat detection enabled
- `cloudwatch-alarm-action-check` - Alerts configured
- `securityhub-enabled` - Security Hub aggregating findings

### AWS Resources Evaluated
- CloudTrail trails and log analysis
- CloudWatch alarms and metrics
- GuardDuty detectors
- Security Hub standards
- Config rules evaluation

## Expected Evidence Fields
- `resource_type`: AWS::CloudTrail::Trail, AWS::GuardDuty::Detector
- `compliance_type`: COMPLIANT, NON_COMPLIANT
- `annotation`: Monitoring configuration and alert status
- `timestamp`: Last monitoring check timestamp

## Remediation Guidance
To implement effective system monitoring:
1. Enable CloudTrail in all regions for audit trails
2. Deploy GuardDuty for intelligent threat detection
3. Configure CloudWatch alarms for critical security events
4. Enable AWS Security Hub for centralized monitoring
5. Set up SNS topics for alert notifications
6. Establish incident response runbooks
7. Review security findings weekly

## Monitoring Objectives
System monitoring must detect:
- Unauthorized access attempts
- Configuration changes to critical resources
- Privilege escalation attempts
- Data exfiltration patterns
- Anomalous API calls
- Failed authentication events

## Security Considerations
- **OWASP AAI05 - Insufficient Agent Monitoring**: AI agents require additional monitoring for unexpected behaviors
- **OWASP LLM04 - Model Denial of Service**: Monitor for resource exhaustion attacks
- Continuous monitoring is critical for detecting agent misuse

## References
- AICPA Trust Services Criteria: CC7.2
- AWS GuardDuty: https://aws.amazon.com/guardduty/
- AWS Security Hub: https://aws.amazon.com/security-hub/

## Keywords
system monitoring, anomaly detection, CloudTrail, GuardDuty, security monitoring, threat detection, SIEM, alerting, incident detection, continuous monitoring
