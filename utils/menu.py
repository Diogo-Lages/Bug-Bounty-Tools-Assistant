from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from BugBountyToolsAssistant.tools import recon, exploitation, miscellaneous

console = Console()

CATEGORIES = {
    "Recon": [
        "Subdomain Enumeration", "Port Scanning", "Screenshots",
        "Technologies", "Content Discovery", "Links",
        "Parameters", "Fuzzing"
    ],
    "Exploitation": [
        "Command Injection", "CORS Misconfiguration", "CRLF Injection",
        "CSRF Injection", "Directory Traversal", "File Inclusion",
        "GraphQL Injection", "Header Injection", "Insecure Deserialization",
        "Insecure Direct Object References", "Open Redirect", "Race Condition",
        "Request Smuggling", "Server Side Request Forgery", "SQL Injection",
        "XSS Injection", "XXE Injection", "SSTI Injection"
    ],
    "Miscellaneous": [
        "Passwords", "Secrets", "Git", "Buckets", "CMS",
        "JSON Web Token", "postMessage", "Subdomain Takeover",
        "Vulnerability Scanners", "Useful"
    ]
}

def display_main_menu():
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Number", style="dim", width=6)
    table.add_column("Category", style="dim")
    table.add_column("Tools", style="dim")

    categories = list(CATEGORIES.keys())
    for i, category in enumerate(categories, 1):
        tools = CATEGORIES[category]
        table.add_row(
            str(i),
            f"[bold cyan]{category}[/bold cyan]",
            "\n".join(tools)
        )
        if i < len(categories):
            table.add_row("", "", "───────────────────────────")

    console.print(table)
    choices = [str(i) for i in range(1, len(categories) + 1)] + ["back"]
    choice = Prompt.ask(
        "\n[yellow]Select a category number or type 'back'[/yellow]",
        choices=choices,
        default="back"
    )

    if choice == "back":
        return "exit"
    return list(CATEGORIES.keys())[int(choice) - 1]

def handle_tool_selection(category):
    tools = CATEGORIES[category]

    while True:
        console.print(f"\n[bold cyan]{category} Tools:[/bold cyan]")
        for i, tool in enumerate(tools, 1):
            console.print(f"{i}. {tool}")

        choices = [str(i) for i in range(1, len(tools) + 1)] + ["back"]
        choice = Prompt.ask(
            "\n[yellow]Select a tool number or type 'back'[/yellow]",
            choices=choices,
            default="back"
        )

        if choice == "back":
            return

        selected_tool = tools[int(choice) - 1]

        if category == "Recon":
            tools_module = recon
        elif category == "Exploitation":
            tools_module = exploitation
        else:
            tools_module = miscellaneous

        tools_module.handle_tool_commands(selected_tool)