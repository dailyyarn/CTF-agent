import json
import shutil
from pathlib import Path

from ctf_agent.adapters.base import BaseChallengeAdapter
from ctf_agent.core.models import Challenge


class ManualJsonAdapter(BaseChallengeAdapter):
    def load_challenge(self, source_path):
        source_path = Path(source_path)
        data = json.loads(source_path.read_text(encoding="utf-8"))

        attachments = []
        for item in data.get("attachments", []):
            attachment_path = Path(item)
            if not attachment_path.is_absolute():
                attachment_path = (source_path.parent / attachment_path).resolve()
            attachments.append(attachment_path)

        return Challenge(
            contest_id=data.get("contest_id", "manual"),
            challenge_id=data.get("challenge_id", source_path.stem),
            title=data.get("title", source_path.stem),
            category=data.get("category", "web"),
            description=data.get("description", ""),
            attachments=attachments,
            target=data.get("target"),
            flag_format=data.get("flag_format"),
            metadata=dict(data.get("metadata", {})),
        )

    def stage_attachments(self, challenge, attachments_dir):
        attachments_dir = Path(attachments_dir)
        attachments_dir.mkdir(parents=True, exist_ok=True)
        staged = []

        for item in challenge.attachments:
            if not item.exists():
                continue
            target_path = attachments_dir / item.name
            if item.resolve() != target_path.resolve():
                shutil.copy2(str(item), str(target_path))
            staged.append(target_path)

        return staged
