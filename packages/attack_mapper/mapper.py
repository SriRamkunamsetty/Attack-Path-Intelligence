"""Rule-based MITRE ATT&CK Mapping Engine."""

from __future__ import annotations

import re
from typing import Dict, List, Optional
from packages.attack_mapper.kb import AttackKnowledgeBase
from packages.schemas.models import (
    AttackStep,
    Observation,
    ReviewStatus,
    TechniqueMappingRecord,
)


class TechniqueMapper:
    """Maps security observations and attack steps to MITRE ATT&CK techniques with defensible rationale."""

    def __init__(self, kb: Optional[AttackKnowledgeBase] = None) -> None:
        self.kb = kb or AttackKnowledgeBase()

    def map_observation(self, obs: Observation) -> List[TechniqueMappingRecord]:
        records: List[TechniqueMappingRecord] = []
        text = f"{obs.category} {obs.description} {obs.raw_payload}".lower()

        # Rule 1: Brute Force / Password Spraying / Failed Logins
        if "fail" in text and ("login" in text or "auth" in text or "password" in text):
            tech = self.kb.get_by_id("T1110")
            if tech:
                records.append(
                    TechniqueMappingRecord(
                        mapping_id=f"map-{obs.id}-T1110",
                        target_id=obs.id,
                        technique_id=tech.technique_id,
                        technique_name=tech.name,
                        rationale=(
                            f"Observation indicates authentication failures. Candidate technique is {tech.name}. "
                            "Requires correlation with event volume, time window, and target accounts."
                        ),
                        supporting_evidence=[obs.id],
                        missing_evidence_required=[
                            "Account-level event correlation",
                            "Confirmation that events belong to the same attacker session",
                            "Distribution across single vs multiple usernames",
                        ],
                        status=ReviewStatus.REQUIRES_REVIEW,
                    )
                )

        # Rule 2: LSASS Memory Access / Credential Dumping
        if "lsass" in text or "mimikatz" in text or "sekurlsa" in text or "procdump" in text:
            tech = self.kb.get_by_id("T1003.001")
            if tech:
                records.append(
                    TechniqueMappingRecord(
                        mapping_id=f"map-{obs.id}-T1003.001",
                        target_id=obs.id,
                        technique_id=tech.technique_id,
                        technique_name=tech.name,
                        rationale=(
                            "Observation detects access or memory dump targeting the LSASS process, "
                            "strongly characteristic of credential dumping."
                        ),
                        supporting_evidence=[obs.id],
                        missing_evidence_required=[
                            "Parent process command-line arguments",
                            "Verification whether target was legitimate antivirus/diagnostic memory dump",
                        ],
                        status=ReviewStatus.ACCEPTED if "lsass memory dump" in text else ReviewStatus.REQUIRES_REVIEW,
                    )
                )

        # Rule 3: PowerShell Script Execution
        if "powershell" in text or "pwsh" in text:
            tech = self.kb.get_by_id("T1059.001")
            if tech:
                records.append(
                    TechniqueMappingRecord(
                        mapping_id=f"map-{obs.id}-T1059.001",
                        target_id=obs.id,
                        technique_id=tech.technique_id,
                        technique_name=tech.name,
                        rationale="Observation explicitly records execution of PowerShell commands or scripts.",
                        supporting_evidence=[obs.id],
                        missing_evidence_required=[
                            "Full script block logging (Event ID 4104)",
                            "Decoded script contents if encoded (-enc / -EncodedCommand)",
                        ],
                        status=ReviewStatus.ACCEPTED if "command execution" in text or "process creation" in text else ReviewStatus.REQUIRES_REVIEW,
                    )
                )

        # Rule 4: Remote Desktop Protocol (RDP) Lateral Movement
        if "rdp" in text or "port 3389" in text or "remote desktop" in text or "mstsc" in text:
            tech = self.kb.get_by_id("T1021.001")
            if tech:
                records.append(
                    TechniqueMappingRecord(
                        mapping_id=f"map-{obs.id}-T1021.001",
                        target_id=obs.id,
                        technique_id=tech.technique_id,
                        technique_name=tech.name,
                        rationale="Network or logon observation indicates RDP session connection.",
                        supporting_evidence=[obs.id],
                        missing_evidence_required=[
                            "Source IP and client hostname correlation",
                            "Confirmation whether session was initiated by authorized IT administration",
                        ],
                        status=ReviewStatus.REQUIRES_REVIEW,
                    )
                )

        # Rule 5: Cloud Storage Access / S3 / Blob Access
        if "s3" in text or "blob" in text or "cloud storage" in text or "bucket" in text:
            tech = self.kb.get_by_id("T1530")
            if tech:
                records.append(
                    TechniqueMappingRecord(
                        mapping_id=f"map-{obs.id}-T1530",
                        target_id=obs.id,
                        technique_id=tech.technique_id,
                        technique_name=tech.name,
                        rationale="Access to cloud storage container or bucket observed.",
                        supporting_evidence=[obs.id],
                        missing_evidence_required=[
                            "Data volume transferred",
                            "Data sensitivity classification of accessed keys/objects",
                        ],
                        status=ReviewStatus.REQUIRES_REVIEW,
                    )
                )

        # Rule 6: Phishing Attachment
        if "phish" in text or "malicious email" in text or "attachment" in text and "email" in text:
            tech = self.kb.get_by_id("T1566.001")
            if tech:
                records.append(
                    TechniqueMappingRecord(
                        mapping_id=f"map-{obs.id}-T1566.001",
                        target_id=obs.id,
                        technique_id=tech.technique_id,
                        technique_name=tech.name,
                        rationale="Inbound email observation with suspicious payload attachment.",
                        supporting_evidence=[obs.id],
                        missing_evidence_required=[
                            "Message trace and headers",
                            "User click or execution confirmation",
                        ],
                        status=ReviewStatus.ACCEPTED if "malicious attachment" in text else ReviewStatus.REQUIRES_REVIEW,
                    )
                )

        return records

    def map_attack_step(self, step: AttackStep) -> List[TechniqueMappingRecord]:
        records: List[TechniqueMappingRecord] = []
        text = f"{step.title} {step.description} {step.stage}".lower()

        # Match against known technique names in knowledge base
        for tech in self.kb.list_all():
            if tech.name.lower() in text or tech.technique_id.lower() in text:
                records.append(
                    TechniqueMappingRecord(
                        mapping_id=f"map-{step.id}-{tech.technique_id}",
                        target_id=step.id,
                        technique_id=tech.technique_id,
                        technique_name=tech.name,
                        rationale=f"Attack step '{step.title}' explicitly references or corresponds to ATT&CK {tech.name}.",
                        supporting_evidence=[],
                        missing_evidence_required=["Direct telemetry verifying this step actually executed"],
                        status=ReviewStatus.REQUIRES_REVIEW,
                    )
                )

        return records
