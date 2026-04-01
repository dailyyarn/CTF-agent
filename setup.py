from setuptools import find_packages, setup


setup(
    name="ctf-agent",
    version="1.0.0",
    description="Windows-first authorized CTF agent with MCP hub, local toolkit integration, and reproducible workspaces.",
    packages=find_packages(include=["ctf_agent", "ctf_agent.*"]),
    include_package_data=True,
    package_data={
        "ctf_agent": [
            "web_templates/*.html",
            "knowledge/embedded_ctf_skills/LICENSE",
            "knowledge/embedded_ctf_skills/README.md",
            "knowledge/embedded_ctf_skills/.gitignore",
            "knowledge/embedded_ctf_skills/*/*.md",
        ]
    },
    install_requires=[
        "paramiko>=3.5.0",
        "selenium>=4.27.0",
    ],
    extras_require={
        "web": [
            "fastapi>=0.115.0",
            "jinja2>=3.1.0",
            "python-multipart>=0.0.9",
            "uvicorn>=0.30.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "ctf-agent=ctf_agent.__main__:main",
            "ctf-agent-mcp=ctf_agent.mcp_server:main",
            "ctf-agent-browser-mcp=ctf_agent.browser_mcp_server:main",
        ]
    },
)
