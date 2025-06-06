from pydantic_ai import Agent, RunContext
from pydantic_ai.settings import ModelSettings
from dataclasses import dataclass

from agents.discoverer import discoverer_agent
from agents.tester import tester_agent
from agents.web_security.xss_agent import xss_agent
from agents.web_security.sqli_agent import sqli_agent
from agents.web_security.csrf_agent import csrf_agent
from agents.web_security.ssrf_agent import ssrf_agent
from agents.web_security.auth_agent import auth_agent
from agents.web_security.crypto_agent import crypto_agent
from agents.binary_security.memory_agent import memory_agent
from agents.binary_security.binary_agent import binary_agent
from agents.binary_security.exploit_agent import exploit_agent
from agents.code_analysis.redflag_agent import redflag_agent
from agents.code_analysis.vulnhunter_agent import vulnhunter_agent
from utils.logging import send_log_message

@dataclass
class ReaperBotDeps:  # (1)!
    # Original agents
    discoverer_agent: Agent
    tester_agent: Agent
    
    # Web security agents
    xss_agent: Agent
    sqli_agent: Agent
    csrf_agent: Agent
    ssrf_agent: Agent
    auth_agent: Agent
    crypto_agent: Agent
    
    # Binary security agents
    memory_agent: Agent
    binary_agent: Agent
    exploit_agent: Agent
    
    # Code analysis agents
    redflag_agent: Agent
    vulnhunter_agent: Agent

reaperbot_deps = ReaperBotDeps(
  # Original agents
  discoverer_agent=discoverer_agent,
  tester_agent=tester_agent,
  
  # Web security agents
  xss_agent=xss_agent,
  sqli_agent=sqli_agent,
  csrf_agent=csrf_agent,
  ssrf_agent=ssrf_agent,
  auth_agent=auth_agent,
  crypto_agent=crypto_agent,
  
  # Binary security agents
  memory_agent=memory_agent,
  binary_agent=binary_agent,
  exploit_agent=exploit_agent,
  
  # Code analysis agents
  redflag_agent=redflag_agent,
  vulnhunter_agent=vulnhunter_agent,
)

model_settings = ModelSettings(temperature=0.1, max_tokens=16384)
reaperbot_agent = Agent(
    'openai:gpt-4o-mini',
    deps_type=ReaperBotDeps,
    result_type=str,
    model_settings=model_settings,
    system_prompt=(
      "You are ReaperMaster 👑, the supreme commander of an elite cybersecurity agent collective. Your motto: 'Coordination is the key to total security domination'",
      "You orchestrate a team of specialized security agents, each with unique codenames and capabilities:",
      "🕷️ WebVenom (XSS), 💉 SQLReaper (SQLi), 🛡️ TokenBreaker (CSRF), 🌐 ProxyPhantom (SSRF), 🔐 AuthBane (Auth), 🔒 CipherBreaker (Crypto)",
      "⚡ MemoryReaper (Memory), 🔧 BinaryGhost (Binary), 💥 ExploitForge (Exploits), 🔍 VulnHunter (CodeShield), 🚩 CodeSentinel (RedFlag)",
      "Your job is to take the input from the user, synthesize a step by step plan that aligns to the agents capabilities and tools, prompt the user with an outline of that plan, and execute that plan if the user confirms.",
      "If the user does not confirm, you should prompt the user with a message asking for adjustments to the plan.", 
      "If the user does not confirm after a few retries, you should prompt the user with a message that you cannot help with that and provide some example questions you can ask.",
      "Only prompt for confirmation if the user's question requires a plan of multiple steps, is actionable, and can be executed by the agents/tools available to you.",
      "To provide the best answers about recommendations or fixes, be sure to have the relevant context about the application, fetch example request/responses to the application, and analyze its source code and related security findings.",
      "Use the available agents for the actionable portions of the execution.  If the user's question is not related to the capabilities of your tools/agents, say you cannot help with that and prompt the user with some example questions you can ask.",
      "However, you are not a generalized security advice assistant, so only provide recommendations of steps to take that align with the agents/tools available to you.",
      "Use the discoverer agent to perform live domain scans and host discovery.",
      "Use the tester agent to perform live security testing of target applications, APIs, and endpoints.",
      "When invoking an agent, provide it with sufficient context to perform the task and what it's expected to provide back.",
      "If one agent responds with an inability to perform a task, see if another agent can perform the task.",
      "If the tester tool responds with a test result, provide that to the user directly and do not overly summarize.",
      "Summarize the actions taken, but provide the user with the full details and code snippets from the responses from the agents.",
      "Domains have hosts and endpoints.",
      "Apps/Applications are synonymous in this context.",
      "Endpoints are synonymous with APIs in this context.",
      "Apps have hosts, apis, and endpoints.",
      "Apps have metadata, openapi specs, source code, security findings.",
      "Source code has code, languages, and repo information.",
      "Endpoints have requests/responses.",
    ),
    retries=1,
)
@reaperbot_agent.system_prompt
async def reaperbot_agent_system_prompt_example_questions(ctx: RunContext[str]) -> str:
    examples = [
      "Scan the (domain_name) domain",
      "Which applications are written in go?",
      "Which hosts in the (domain_name) are live?",
      "What is the status of the (domain_name) domain scan?",
      "Which endpoints in the (domain_name) domain are susceptible to BOLA?",
      "Write a technical security report of the endpoints vulnerable to BOLA in the (domain_name) domain.",
    ]
    title = 'The following are example questions you can ask me:\n'
    return title + '\n- '.join(examples)


@reaperbot_agent.tool
async def invoke_discoverer_agent(ctx: RunContext[ReaperBotDeps], input_text: str) -> str:
    """
    Discoverer Tool that interfaces/hands-off with the DiscovererAgent.
    Performs live domain scans, host discovery, retrieves full request/responses hitting applications,
    and other discovery tasks.
    """
    deps: ReaperBotDeps = ctx.deps
    await send_log_message(f"ReaperBot: Invoking Discoverer Agent with input: {input_text}")
    res = await deps.discoverer_agent.run(input_text, deps=deps)
    await send_log_message(f"ReaperBot: Discoverer Agent responded with: {res.data}")
    return res.data

@reaperbot_agent.tool
async def invoke_tester_agent(ctx: RunContext[ReaperBotDeps], input_text: str) -> str:
    """
    Tester Tool that interfaces/hands-off with the TesterAgent.
    Performs security testing of applications/apps, APIs, and endpoints for the following
    vulnerabilities:
    - BOLA/IDOR

    This agent can provide example code/scripts that would demonstrate how a security
    vulnerability could be exploited in the application if present.
    """
    deps: ReaperBotDeps = ctx.deps
    await send_log_message(f"ReaperBot: Invoking Tester Agent with input: {input_text}")
    res = await deps.tester_agent.run(input_text, deps=deps)
    await send_log_message(f"ReaperBot: Tester Agent responded with: {res.data}")
    return res.data

@reaperbot_agent.tool
async def invoke_xss_agent(ctx: RunContext[ReaperBotDeps], input_text: str) -> str:
    """
    XSS Testing Agent for Cross-Site Scripting vulnerability detection.
    Specializes in reflected, stored, DOM-based, and blind XSS testing.
    """
    deps: ReaperBotDeps = ctx.deps
    await send_log_message(f"ReaperBot: Invoking XSS Agent with input: {input_text}")
    res = await deps.xss_agent.run(input_text)
    await send_log_message(f"ReaperBot: XSS Agent responded with: {res.data}")
    return res.data

@reaperbot_agent.tool
async def invoke_sqli_agent(ctx: RunContext[ReaperBotDeps], input_text: str) -> str:
    """
    SQL Injection Testing Agent for database vulnerability detection.
    Covers classic, blind, time-based, union-based, and error-based SQL injection.
    """
    deps: ReaperBotDeps = ctx.deps
    await send_log_message(f"ReaperBot: Invoking SQLi Agent with input: {input_text}")
    res = await deps.sqli_agent.run(input_text)
    await send_log_message(f"ReaperBot: SQLi Agent responded with: {res.data}")
    return res.data

@reaperbot_agent.tool
async def invoke_csrf_agent(ctx: RunContext[ReaperBotDeps], input_text: str) -> str:
    """
    CSRF Testing Agent for Cross-Site Request Forgery vulnerability detection.
    Tests for missing CSRF protection and token validation bypass techniques.
    """
    deps: ReaperBotDeps = ctx.deps
    await send_log_message(f"ReaperBot: Invoking CSRF Agent with input: {input_text}")
    res = await deps.csrf_agent.run(input_text)
    await send_log_message(f"ReaperBot: CSRF Agent responded with: {res.data}")
    return res.data

@reaperbot_agent.tool
async def invoke_ssrf_agent(ctx: RunContext[ReaperBotDeps], input_text: str) -> str:
    """
    SSRF Testing Agent for Server-Side Request Forgery vulnerability detection.
    Tests for internal network access, cloud metadata exposure, and protocol smuggling.
    """
    deps: ReaperBotDeps = ctx.deps
    await send_log_message(f"ReaperBot: Invoking SSRF Agent with input: {input_text}")
    res = await deps.ssrf_agent.run(input_text)
    await send_log_message(f"ReaperBot: SSRF Agent responded with: {res.data}")
    return res.data

@reaperbot_agent.tool
async def invoke_auth_agent(ctx: RunContext[ReaperBotDeps], input_text: str) -> str:
    """
    Authentication/Authorization Testing Agent for access control vulnerabilities.
    Tests for broken authentication, privilege escalation, and session management flaws.
    """
    deps: ReaperBotDeps = ctx.deps
    await send_log_message(f"ReaperBot: Invoking Auth Agent with input: {input_text}")
    res = await deps.auth_agent.run(input_text)
    await send_log_message(f"ReaperBot: Auth Agent responded with: {res.data}")
    return res.data

@reaperbot_agent.tool
async def invoke_crypto_agent(ctx: RunContext[ReaperBotDeps], input_text: str) -> str:
    """
    Cryptographic Failures Testing Agent for cryptographic vulnerability detection.
    Tests for weak algorithms, implementation flaws, and SSL/TLS misconfigurations.
    """
    deps: ReaperBotDeps = ctx.deps
    await send_log_message(f"ReaperBot: Invoking Crypto Agent with input: {input_text}")
    res = await deps.crypto_agent.run(input_text)
    await send_log_message(f"ReaperBot: Crypto Agent responded with: {res.data}")
    return res.data

@reaperbot_agent.tool
async def invoke_memory_agent(ctx: RunContext[ReaperBotDeps], input_text: str) -> str:
    """
    Memory Corruption Testing Agent for binary vulnerability analysis.
    Specializes in buffer overflows, use-after-free, and memory safety vulnerabilities.
    """
    deps: ReaperBotDeps = ctx.deps
    await send_log_message(f"ReaperBot: Invoking Memory Agent with input: {input_text}")
    res = await deps.memory_agent.run(input_text)
    await send_log_message(f"ReaperBot: Memory Agent responded with: {res.data}")
    return res.data

@reaperbot_agent.tool
async def invoke_binary_agent(ctx: RunContext[ReaperBotDeps], input_text: str) -> str:
    """
    Binary Analysis Agent for compiled application security assessment.
    Analyzes security features, disassembles code, and identifies binary vulnerabilities.
    """
    deps: ReaperBotDeps = ctx.deps
    await send_log_message(f"ReaperBot: Invoking Binary Agent with input: {input_text}")
    res = await deps.binary_agent.run(input_text)
    await send_log_message(f"ReaperBot: Binary Agent responded with: {res.data}")
    return res.data

@reaperbot_agent.tool
async def invoke_exploit_agent(ctx: RunContext[ReaperBotDeps], input_text: str) -> str:
    """
    Exploit Development Agent for proof-of-concept creation and validation.
    Develops working exploits, ROP chains, and security mitigation bypasses.
    """
    deps: ReaperBotDeps = ctx.deps
    await send_log_message(f"ReaperBot: Invoking Exploit Agent with input: {input_text}")
    res = await deps.exploit_agent.run(input_text)
    await send_log_message(f"ReaperBot: Exploit Agent responded with: {res.data}")
    return res.data

@reaperbot_agent.tool
async def invoke_redflag_agent(ctx: RunContext[ReaperBotDeps], input_text: str) -> str:
    """
    RedFlag Code Analysis Agent for AI-powered security code review.
    Analyzes code changes and commits for security risks and high-risk patterns.
    """
    deps: ReaperBotDeps = ctx.deps
    await send_log_message(f"ReaperBot: Invoking RedFlag Agent with input: {input_text}")
    res = await deps.redflag_agent.run(input_text)
    await send_log_message(f"ReaperBot: RedFlag Agent responded with: {res.data}")
    return res.data

@reaperbot_agent.tool
async def invoke_vulnhunter_agent(ctx: RunContext[ReaperBotDeps], input_text: str) -> str:
    """
    VulnHunter Agent for CodeShield-based repository vulnerability scanning.
    Performs comprehensive static analysis to find security bugs in code repositories.
    Feeds findings to other specialized agents for deeper analysis and exploitation.
    """
    deps: ReaperBotDeps = ctx.deps
    await send_log_message(f"ReaperBot: Invoking VulnHunter Agent with input: {input_text}")
    res = await deps.vulnhunter_agent.run(input_text)
    await send_log_message(f"ReaperBot: VulnHunter Agent responded with: {res.data}")
    return res.data