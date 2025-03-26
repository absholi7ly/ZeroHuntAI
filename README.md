# 📖ZeroHuntAI - AI-Powered Zero-Day Vulnerability Scanner
ZeroHuntAI is an advanced, modular, and extensible source code vulnerability scanner designed to detect zero-day exploits and security weaknesses in local directories or GitHub repositories. Leveraging static code analysis, pattern matching, and AI-driven risk scoring, ZeroHuntAI empowers developers and security researchers to identify and mitigate threats like RCE, SQL Injection, XSS, and more.

![ZeroHuntAI Logo](path/to/image.png)
## ✨ Key Features
* Multi-Mode Scanning:
Local Scanner: Recursively analyzes .py, .php, .js, .java, .c, .cpp, .go, and more.
GitHub Scanner: Clones and scans repositories directly from URLs.
Vulnerability Detection:
Buffer Overflow, SQL Injection, Command Injection, Path Traversal, XSS, Authentication Flaws, Logic Bugs, and more.
Extracts secrets from .env and configuration files.
Advanced Analysis:
AST-based parsing for deep code insights.
Regex pattern matching for risky functions (e.g., eval(), system(), mysqli_query()).
Contextual vulnerability detection and data flow analysis.
AI Risk Scoring:
Mock LLM evaluation (placeholder) to classify risks as High, Medium, or Low.
Future-ready for integration with models like GPT-4 or LLaMA.
Reporting:
JSON and HTML reports with detailed findings.
Interactive Call Graph & Taint Flow Visualization.
Exploitation Simulation:
Runs simulated exploits (e.g., SQLi, XSS) in an isolated Docker environment.
User Experience:
CLI with colored output (via rich or colorama).
Web dashboard for interactive report browsing.
Scanner Demo
🚀 Getting Started
Prerequisites
Python 3.8+
Required libraries: gitpython, ast, colorama, requests, tqdm, etc. (see requirements.txt).
Installation
Clone the repository:
bash
git clone https://github.com/yourusername/ZeroHuntAI.git
cd ZeroHuntAI
Install dependencies:
bash
pip install -r requirements.txt
Usage Examples
Scan a local directory:
bash
python main.py --mode local --path /path/to/code
Scan a GitHub repository:
bash
python main.py --mode github --repo https://github.com/target/repo.git
Enable Call Graph visualization:
bash
python main.py --mode local --path /path/to/code --enable-call-graph
CLI Output
🛠️ Project Structure
ZeroHuntAI/
├── main.py               # CLI interface
├── scanner/             # Scanning modules
│   ├── local_scanner.py  # Local directory scanner
│   ├── github_scanner.py # GitHub repo scanner
│   ├── analyzer.py       # AST & pattern analysis
│   ├── ai_model.py       # AI risk scoring (mock)
│   └── report_generator.py # Report generation
├── utils/               # Utility modules
│   ├── file_utils.py     # File handling
│   └── logger.py         # Logging with colors
├── output/              # Generated reports
├── requirements.txt      # Dependencies
├── README.md            # Project documentation
└── LICENSE              # MIT License
🌟 Advanced Features
Exploitation Simulation Engine:
Simulates exploits in a Docker sandbox and reports success (✅) or failure (❌).
Data Flow & Taint Analysis:
Tracks variables from input to execution using tools like Bandit or Semgrep.
Auto PoC Generator:
Generates Python/Bash exploit scripts and PDF reports for each vulnerability.
API Endpoint Analysis:
Extracts and tests endpoints for IDOR, SSRF, and Auth Bypass.
Interactive Call Graph:
Visualizes function relationships and data flow in an HTML graph.
Highlights exploitable paths in red.
Call Graph
Secrets Detection:
Finds API keys, tokens, and sensitive data in code or configs.
Threat Intelligence:
Integrates with CVE feeds to cross-check findings.
AI Fuzzer:
Generates random payloads to test for Buffer Overflows and Logic Bugs.
Auto Patch Generator:
Suggests secure code fixes for detected issues.
🔮 Future Roadmap
Full LLM integration (e.g., ChatGPT, GPT-4) for intelligent analysis.
Dockerfile and Kubernetes YAML misconfiguration scanning.
Reverse AI Vulnerability Generator for novel exploit scenarios.
CI/CD pipeline integration (GitHub Actions, Jenkins, etc.).
Real-time web dashboard with historical scan tracking.
📋 Requirements
Install all dependencies with:
bash
pip install -r requirements.txt
Key libraries:
gitpython: For GitHub repo cloning.
ast: For Abstract Syntax Tree parsing.
colorama / rich: For CLI aesthetics.
requests: For API and web interactions.
tqdm: For progress bars.
📜 License
This project is licensed under the MIT License - see the LICENSE file for details.
🙌 Credits
Built with ❤️ by [Your Name].
Inspired by open-source SAST tools and the security research community.
Report Sample

💻 Contribution and development
Hello to all security researchers and developers to contribute to the development of ZeroHuntAI
To contribute:
* Fork Warehouse
* Add your feature
* Open Pull Request


⚠️ Legal Disclaimer
For educational use only. Unauthorized use is your responsibility.
⭐ Support the project by giving it a Star!

