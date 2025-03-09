# Bug Bounty Tools Assistant

An interactive CLI tool designed to assist bug bounty hunters and security testers with various commands and tools for Recon, Exploitation, and Miscellaneous tasks.

## Features
- **Interactive Menu**: Navigate through categories like Recon, Exploitation, and Miscellaneous with ease.
- **Command Execution**: Select tools and execute their associated commands directly from the CLI.
- **Clipboard Support**: Commands are copied to your clipboard for quick use.
- **Rich Output**: Clear and visually appealing output using the `rich` library.
- **Simulated Execution**: Commands can be simulated for testing purposes without running them in a real environment.
- **Extensible**: Easily add new tools or categories by modifying the code structure.

## Requirements
- Python 3.x
- Libraries: `rich`, `pyperclip`

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Diogo-Lages/Bug-Bounty-Tools-Assistant.git
   ```
2. Navigate to the project directory:
   ```bash
   cd Bug-Bounty-Tools-Assistant
   ```
3. Install the required libraries manually:
   ```bash
   pip install rich pyperclip
   ```

## Usage
1. Run the main script:
   ```bash
   python main.py
   ```
2. Use the interactive menu to select a category (e.g., Recon, Exploitation).
3. Choose a tool from the selected category.
4. The tool's command will be displayed, copied to your clipboard, and optionally executed.

## Code Structure
- **main.py**: Entry point of the application. Displays the main menu and handles user interaction.
- **utils/menu.py**: Contains functions for displaying the main menu and handling tool selection.
- **tools/**: Directory containing modules for different categories (`recon.py`, `exploitation.py`, `miscellaneous.py`).
- **command_executor.py**: Handles the execution or simulation of commands.
- **LICENSE**: License file for the project.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
