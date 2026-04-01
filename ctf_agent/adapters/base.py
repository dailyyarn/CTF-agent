from abc import ABC, abstractmethod


class BaseChallengeAdapter(ABC):
    @abstractmethod
    def load_challenge(self, source_path):
        raise NotImplementedError

    def stage_attachments(self, challenge, attachments_dir):
        return list(challenge.attachments)

    def prepare_target(self, challenge):
        return challenge.target

    def submit_flag(self, challenge, flag):
        return {
            "status": "skipped",
            "reason": "no submission adapter configured",
            "flag": flag,
        }
