$ErrorActionPreference = 'Stop'

# LLM
$env:CTF_AGENT_LLM_API_KEY = '<YOUR_API_KEY>'
$env:CTF_AGENT_LLM_BASE_URL = 'https://api.openai.com/v1'
$env:CTF_AGENT_LLM_MODEL = 'gpt-4o'

# Browser MCP
$env:CTF_AGENT_BROWSER_KIND = 'chrome'
$env:CTF_AGENT_BROWSER_BINARY = 'C:\Program Files\Google\Chrome\Application\chrome.exe'

# Optional OOB / blind probing
$env:CTF_AGENT_OOB_BASE_URL = 'https://oob.example.com'
$env:CTF_AGENT_OOB_POLL_URL_TEMPLATE = 'https://oob.example.com/poll/{token}'
$env:CTF_AGENT_OOB_AUTH_TOKEN = '<OPTIONAL_OOB_TOKEN>'

# Optional remote helpers
$env:CTF_AGENT_REMOTE_PRIMARY_PASSWORD = '<SSH_PASSWORD>'

# Optional IDA MCP sidecar
$env:CTF_AGENT_IDA_MCP_PYTHON = 'D:\ctf-sidecars\ida-pro-mcp\Scripts\python.exe'
$env:CTF_AGENT_IDA_MCP_SERVER = 'D:\ctf-sidecars\ida-pro-mcp\Lib\site-packages\ida_pro_mcp\server.py'

# Optional x64dbg MCP sidecar
$env:CTF_AGENT_X64DBG_MCP_PYTHON = 'D:\ctf-sidecars\x64dbg-automate\Scripts\python.exe'
$env:CTF_AGENT_X64DBG_PATH = 'D:\tools\x64dbg'
