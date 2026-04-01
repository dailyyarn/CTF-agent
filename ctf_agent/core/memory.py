from ctf_agent.core.models import ActionRecord, CandidateFlag, ExploitPlan, Finding
from ctf_agent.core.verifier import FlagVerifier


_FLAG_VERIFIER = FlagVerifier()


class StateMemory(object):
    def __init__(self, state):
        self.state = state

    def add_hypothesis(self, hypothesis):
        if hypothesis and hypothesis not in self.state.hypotheses:
            self.state.hypotheses.append(hypothesis)

    def add_finding(self, source, summary, evidence, confidence=0.5):
        self.state.findings.append(
            Finding(
                source=source,
                summary=summary,
                evidence=evidence,
                confidence=confidence,
            )
        )

    def add_candidate_flag(self, value, source, confidence, reproducible=False):
        existing = [item for item in self.state.candidate_flags if item.value == value]
        if existing:
            item = existing[0]
            previous_confidence = float(item.confidence or 0.0)
            previous_reproducible = bool(item.reproducible)
            current_priority = _FLAG_VERIFIER._source_priority(item.source)
            new_priority = _FLAG_VERIFIER._source_priority(source)
            item.confidence = max(item.confidence, confidence)
            item.reproducible = item.reproducible or reproducible
            if (
                new_priority > current_priority
                or (new_priority == current_priority and reproducible and not previous_reproducible)
                or (new_priority == current_priority and confidence > previous_confidence and source)
                or (not item.source and source)
            ):
                item.source = source
            return

        self.state.candidate_flags.append(
            CandidateFlag(
                value=value,
                source=source,
                confidence=confidence,
                reproducible=reproducible,
            )
        )

    def add_exploit_plan(self, title, method, url, data=None, headers=None, notes="", confidence=0.5):
        data = data or {}
        headers = headers or {}
        existing = [
            item
            for item in self.state.exploit_plans
            if item.title == title and item.method == method and item.url == url
        ]
        if existing:
            item = existing[0]
            item.confidence = max(item.confidence, confidence)
            if notes and notes not in item.notes:
                item.notes = (item.notes + "\n" + notes).strip()
            if data:
                item.data.update(data)
            if headers:
                item.headers.update(headers)
            return

        self.state.exploit_plans.append(
            ExploitPlan(
                title=title,
                method=method,
                url=url,
                data=dict(data),
                headers=dict(headers),
                notes=notes,
                confidence=confidence,
            )
        )

    def record_action(self, phase, action, status, summary, artifact=None):
        self.state.tried_actions.append(
            ActionRecord(
                phase=phase,
                action=action,
                status=status,
                summary=summary,
                artifact=artifact,
            )
        )
