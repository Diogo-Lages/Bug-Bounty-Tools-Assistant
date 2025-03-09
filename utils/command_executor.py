import subprocess
import pyperclip
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

console = Console()


def execute_command(command):
    console.print(f"\n[bold green]Selected command:[/bold green] {command}")

    try:
        pyperclip.copy(command)
        console.print("[green]Command copied to clipboard![/green]")
    except:
        console.print("[yellow]Could not copy to clipboard. Manual copy required.[/yellow]")

    if Confirm.ask("Do you want to execute this command?", default=False):
        console.print(Panel.fit("[bold yellow]Executing command...[/bold yellow]"))
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)

            if result.stdout:
                console.print("[bold green]Command Output:[/bold green]")
                console.print(result.stdout)

            if result.stderr:
                console.print("[bold red]Error Output:[/bold red]")
                console.print(result.stderr)

        except Exception as e:
            console.print(f"[bold red]Error executing command:[/bold red] {str(e)}")

    console.print("\nPress Enter to continue...")
    input()


from rich.console import Console

console = Console()


def execute_command(command: str):
    try:
        console.print(f"\n[green]Command: {command}[/green]")
    except Exception as e:
        console.print(f"[red]Error displaying command: {str(e)}[/red]")


import subprocess
from rich.console import Console

console = Console()


def execute_command(command):
    try:
        console.print(f"[bold green]Executing: [/bold green][yellow]{command}[/yellow]")
        console.print(
            "[cyan]This is a simulated execution. In a real environment, this would run the actual command.[/cyan]")

        # In a real environment, you would uncomment this code to actually execute the command
        # process = subprocess.Popen(
        #     command,
        #     shell=True,
        #     stdout=subprocess.PIPE,
        #     stderr=subprocess.PIPE,
        #     text=True
        # )

        # stdout, stderr = process.communicate()

        # if stdout:
        #     console.print(f"[green]Output:[/green]\n{stdout}")
        # if stderr:
        #     console.print(f"[red]Error:[/red]\n{stderr}")

        # return process.returncode == 0

        # For simulation purposes
        console.print("[green]Command simulated successfully[/green]")
        return True
    except Exception as e:
        console.print(f"[red]Error executing command: {str(e)}[/red]")
        return False
