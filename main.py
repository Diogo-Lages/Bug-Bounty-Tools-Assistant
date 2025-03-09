#!/usr/bin/env python3
import sys
print("Python executable:", sys.executable)
print("Python path:", sys.path)

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from utils.menu import display_main_menu, handle_tool_selection

console = Console()

def main():
    try:
        console.print(Panel.fit(
            "[bold yellow]Bug Bounty Tools Assistant[/bold yellow]\n"
            "An interactive CLI for security testing commands",
            border_style="yellow"
        ))

        while True:
            category = display_main_menu()
            if category.lower() == 'exit':
                console.print("[yellow]Goodbye![/yellow]")
                sys.exit(0)

            handle_tool_selection(category)

    except KeyboardInterrupt:
        console.print("\n[yellow]Exiting gracefully...[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]An error occurred: {str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()