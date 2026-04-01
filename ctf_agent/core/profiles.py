from copy import deepcopy

from ctf_agent.knowledge import get_skillpack


BASE_PROFILE = {
    "label": "CTF Profile",
    "language": "zh-CN",
    "goal": "中文输出，持续推进直到拿到可验证的 flag 或明确阻塞点。",
    "capabilities": [],
    "notes": [],
}


def get_profile(category):
    skillpack = get_skillpack(category, default="misc")
    profile = deepcopy(BASE_PROFILE)
    profile["label"] = skillpack.get("label", BASE_PROFILE["label"])
    profile["goal"] = skillpack.get("profile_goal", BASE_PROFILE["goal"])
    profile["capabilities"] = list(skillpack.get("profile_capabilities", []))
    profile["notes"] = list(skillpack.get("profile_notes", []))
    profile["knowledge_topics"] = list(skillpack.get("knowledge_topics", []))
    profile["top_tactics"] = list(skillpack.get("top_tactics", []))
    profile["reference_docs"] = list(skillpack.get("reference_docs", []))
    return profile
