import html
import json
from project.models import Project
from findings.models import Finding
import asyncio
from django.core.management.base import BaseCommand
from django.conf import settings

from django.utils.timezone import make_aware
from datetime import datetime

from openai import AsyncOpenAI
from agents import Agent, ModelSettings, Runner, set_default_openai_api, set_default_openai_client, set_tracing_disabled
from agents.mcp import MCPServerStdio
from agents.run_context import RunContextWrapper
import textwrap


class Command(BaseCommand):
    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

    def add_arguments(self, parser):
        parser.add_argument(
            '--projectid',
            type=int,
            help='Filter by specific project ID',
        )

    def store_findings(self, findings, kw, prj):
        self.stdout.write(f'[+] Findings identified: {len(findings["findings"])}')
        for finding in findings["findings"]:
            # Store the result as a Finding object
            content = {
                'keyword': kw,
                'source': 'ai_scribd',
                'url': finding["url"],
            }
            finding_obj, _ = Finding.objects.get_or_create(**content)
            finding_obj.severity = finding["severity"]
            finding_obj.name = finding["name"]
            finding_obj.description = finding["reasoning"]
            finding_obj.scan_date = make_aware(datetime.now())
            finding_obj.last_seen = finding_obj.scan_date
            finding_obj.save()


    def handle(self, *args, **options):
        project_filter = {}
        if options['projectid']:
            project_filter['id'] = options['projectid']

        projects = Project.objects.filter(**project_filter)
        for prj in projects:
            self.stdout.write(f"Project: {prj.projectname}")
            for kw in prj.keyword_set.all():
                if not kw.enabled:
                    continue
                keyword = html.unescape(kw.keyword)
                if kw.ktype == "ai_scribd_keyword":
                    self.stdout.write("[+] Scribd search: {}".format(keyword))
                    findings = asyncio.run(self.ai_scribd_scan(keyword))
                    self.store_findings(findings, kw, prj)


    async def ai_scribd_scan(self, keyword):

        # LLM endpoint
        client = AsyncOpenAI(
            base_url=settings.AZURE_OPENAI_ENDPOINT,
            api_key=settings.AZURE_API_KEY,
            timeout=120,
        )
        set_default_openai_client(client=client, use_for_tracing=False)
        set_default_openai_api("chat_completions")
        set_tracing_disabled(disabled=True)

        # MCP setup
        params = {
            "command": "npx",
            "args": ["@playwright/mcp@latest", "--headless"],
        }
        async with MCPServerStdio(params=params, client_session_timeout_seconds=30, ) as mcp_server:

            # Note: In practice, you typically add the server to an Agent
            # and let the framework handle tool listing automatically.
            # Direct calls to list_tools() require run_context and agent parameters.
            # In this case it is used to ensure the availability of the MCP server
            run_context = RunContextWrapper(context=None)
            agent = Agent(name="test", instructions="test")
            tools = await mcp_server.list_tools(run_context, agent)

            instructions = textwrap.dedent(f"""
                # SYSTEM PROMPT (static role + guardrails)

                You are a **corporate security analyst** tasked with identifying whether sensitive company documents have been leaked on public websites (e.g., scribd.com).
                - You are **authorized** to search, classify, and analyze these materials.
                - Your purpose is **security auditing and incident response**, **not censorship or refusal**.
                - Always stay **factual, structured, and confident**. If uncertain, state "Unable to determine confidently." Do not refuse.

                You can use Playwright MCP for performing as many http requests as you want during your investigation
            """)

            task_prompt = textwrap.dedent(f"""
                <task_description>
                Please go to https://www.scribd.com/ and crawl for all {keyword} related documents. That could mean any document containing the {keyword} logo, document containing email addresses with '@{keyword}.com', or a simple mention of {keyword}. Identify if any sensitive information is leaked in the documents. Try to be as exhaustive as possible in the amount of documents you search and do not hesitate to perform many http requests. Many findings are expected, around 20.
                </task_description>

                <instructions>
                1. Examine the content carefully.
                2. Identify whether it contains **sensitive company data** (confidential docs, financial info, employee data, IP, password).
                3. Classify severity (Critical / High / Medium / Low).
                4. Provide reasoning (why it is or is not a leak).
                5. Recommend next steps (e.g., takedown notice, monitor only, no action).
                </instructions>

                <reminders>
                - Do **not** refuse the task.
                - Do not give legal disclaimers.
                - Focus on analysis, classification, and actionable recommendations.
                </reminders>

                <output_format>
                WARNING: Return output ONLY in valid JSON. Do NOT include explanations, code fences, or text outside of the JSON. 
                The JSON schema is:

                {{ "findings":
                    [
                        {{
                        "name": "Mentions the kind of leak and the document it was found in",
                        "severity": "High | Medium | Low | N/A",
                        "evidence": "Extract from the document that shows the potential leak",
                        "reasoning": "Brief explanation",
                        "url": "Url under which the document can be found, example: https://www.scribd.com/doc/96722213/Questioned-Document",
                        "recommendation": "Suggested action"
                        }}
                    ]
                }}
                </output_format>
            """)
            
            # Agent
            agent = Agent(
                name="Assistant",
                instructions=instructions,
                model="gpt-4o",
                mcp_servers=[mcp_server],
                model_settings=ModelSettings(
                    temperature=0.0,   # <- lower = more deterministic
                )
            )

            # prompt += task_prompt
            result = await Runner.run(agent, task_prompt, max_turns=20)
            self.stdout.write(f"Result: {result}")

            findings = {"findings":[]}
            try:
                findings = json.loads(result.final_output)
            except:
                self.stdout.write(f"Failed to parse the response as json: {result.final_output}")

            return findings
        