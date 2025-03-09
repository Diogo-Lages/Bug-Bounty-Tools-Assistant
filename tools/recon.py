from rich.console import Console
from rich.prompt import Prompt
from BugBountyToolsAssistant.utils.command_executor import execute_command

console = Console()

TOOL_COMMANDS = {
    "Port Scanning": {
        "Masscan": {
            "1": {
                "name": "Quick Scan",
                "command": "masscan -p1-65535 example.com --rate=1000",
                "description": "Fast scan of all ports at 1000 packets per second"
            },
            "2": {
                "name": "Specific Ports",
                "command": "masscan -p80,443,8080 example.com --rate=500",
                "description": "Scan specific ports at lower rate"
            },
            "3": {
                "name": "With Output",
                "command": "masscan -p1-65535 example.com -oJ output.json",
                "description": "Save results in JSON format"
            },
            "4": {
                "name": "Subnet Scan",
                "command": "masscan 192.168.0.0/16 -p80,443",
                "description": "Scan subnet for specific ports"
            },
            "5": {
                "name": "Intensive Scan",
                "command": "masscan -p0-65535 example.com --rate=10000 --banners",
                "description": "Aggressive scan with banner grabbing"
            }
        },
        "RustScan": {
            "1": {
                "name": "Fast Scan",
                "command": "rustscan -a example.com",
                "description": "Quick scan with default settings"
            },
            "2": {
                "name": "With Ports",
                "command": "rustscan -a example.com -p 80,443,8080",
                "description": "Scan specific ports"
            },
            "3": {
                "name": "Batch Size",
                "command": "rustscan -a example.com -b 500",
                "description": "Adjust batch size for slower networks"
            },
            "4": {
                "name": "Timeout",
                "command": "rustscan -a example.com --timeout 2000",
                "description": "Set custom timeout"
            },
            "5": {
                "name": "With Nmap",
                "command": "rustscan -a example.com -- -A -sC",
                "description": "RustScan with Nmap scripts"
            }
        },
        "Naabu": {
            "1": {
                "name": "Default Scan",
                "command": "naabu -host example.com",
                "description": "Basic port scanning"
            },
            "2": {
                "name": "Silent Mode",
                "command": "naabu -host example.com -silent",
                "description": "Only output found ports"
            },
            "3": {
                "name": "Port Range",
                "command": "naabu -host example.com -p 1-1000",
                "description": "Scan specific port range"
            },
            "4": {
                "name": "Top Ports",
                "command": "naabu -host example.com -top-ports 100",
                "description": "Scan top 100 ports"
            },
            "5": {
                "name": "With Output",
                "command": "naabu -host example.com -json -o output.json",
                "description": "Save results in JSON format"
            }
        },
        "Nmap": {
            "1": {
                "name": "Quick Scan",
                "command": "nmap -F example.com",
                "description": "Fast scan of top ports"
            },
            "2": {
                "name": "Version Detection",
                "command": "nmap -sV -sC example.com",
                "description": "Detect service versions and run scripts"
            },
            "3": {
                "name": "All Ports",
                "command": "nmap -p- example.com",
                "description": "Scan all 65535 ports"
            },
            "4": {
                "name": "UDP Scan",
                "command": "nmap -sU example.com",
                "description": "Scan UDP ports"
            },
            "5": {
                "name": "Aggressive Scan",
                "command": "nmap -A example.com",
                "description": "Aggressive scan with OS detection"
            }
        },
        "ScanCannon": {
            "1": {
                "name": "Basic Scan",
                "command": "scancannon example.com",
                "description": "Default parallel port scan"
            },
            "2": {
                "name": "Custom Range",
                "command": "scancannon example.com --ports 1-1000",
                "description": "Scan specific port range"
            },
            "3": {
                "name": "With Nmap",
                "command": "scancannon example.com --nmap '-sV'",
                "description": "Run with Nmap version detection"
            },
            "4": {
                "name": "Fast Mode",
                "command": "scancannon example.com --fast",
                "description": "Quick scan with less accuracy"
            },
            "5": {
                "name": "Output File",
                "command": "scancannon example.com --output scan.txt",
                "description": "Save results to file"
            }
        }
    },
    "Subdomain Enumeration": {
        "Sublist3r": {
            "1": {
                "name": "Basic Scan",
                "command": "sublist3r -d example.com",
                "description": "Basic subdomain enumeration scan"
            },
            "2": {
                "name": "With Ports",
                "command": "sublist3r -d example.com -p 80,443",
                "description": "Scan with specific ports"
            },
            "3": {
                "name": "Save Output",
                "command": "sublist3r -d example.com -o output.txt",
                "description": "Save results to a file"
            },
            "4": {
                "name": "Verbose Mode",
                "command": "sublist3r -d example.com -v",
                "description": "Show verbose output"
            },
            "5": {
                "name": "Choose Engines",
                "command": "sublist3r -d example.com -e google,yahoo,bing",
                "description": "Use specific search engines"
            }
        },
        "Amass": {
            "1": {
                "name": "Basic Enum",
                "command": "amass enum -d example.com",
                "description": "Basic enumeration mode"
            },
            "2": {
                "name": "Passive Mode",
                "command": "amass enum -passive -d example.com",
                "description": "Passive gathering only"
            },
            "3": {
                "name": "Active Mode",
                "command": "amass enum -active -d example.com -p 80,443",
                "description": "Active enumeration with port scanning"
            },
            "4": {
                "name": "With Output",
                "command": "amass enum -d example.com -o output.txt -json results.json",
                "description": "Save results in text and JSON formats"
            },
            "5": {
                "name": "Intensive Mode",
                "command": "amass enum -d example.com -active -brute -w wordlist.txt",
                "description": "Intensive scan with bruteforce"
            }
        },
        "Findomain": {
            "1": {
                "name": "Quick Scan",
                "command": "findomain -t example.com",
                "description": "Fast subdomain discovery"
            },
            "2": {
                "name": "With Output",
                "command": "findomain -t example.com -o",
                "description": "Save results to file"
            },
            "3": {
                "name": "Resolve IPs",
                "command": "findomain -t example.com -r",
                "description": "Resolve subdomain IPs"
            },
            "4": {
                "name": "Monitor Mode",
                "command": "findomain -t example.com -m",
                "description": "Monitor for new subdomains"
            },
            "5": {
                "name": "Full Scan",
                "command": "findomain -t example.com -r -o -u output.txt",
                "description": "Complete scan with IP resolution and output"
            }
        },
        "Subfinder": {
            "1": {
                "name": "Basic Scan",
                "command": "subfinder -d example.com",
                "description": "Basic subdomain discovery"
            },
            "2": {
                "name": "Silent Mode",
                "command": "subfinder -d example.com -silent",
                "description": "Only output found subdomains"
            },
            "3": {
                "name": "All Sources",
                "command": "subfinder -d example.com -all",
                "description": "Use all available sources"
            },
            "4": {
                "name": "Recursive",
                "command": "subfinder -d example.com -recursive",
                "description": "Recursive subdomain discovery"
            },
            "5": {
                "name": "With Output",
                "command": "subfinder -d example.com -o output.txt",
                "description": "Save results to file"
            }
        },
        "Assetfinder": {
            "1": {
                "name": "Basic Search",
                "command": "assetfinder example.com",
                "description": "Basic asset discovery"
            },
            "2": {
                "name": "Subdomains Only",
                "command": "assetfinder --subs-only example.com",
                "description": "Only find subdomains"
            },
            "3": {
                "name": "With Output",
                "command": "assetfinder example.com > output.txt",
                "description": "Save results to file"
            },
            "4": {
                "name": "Unique Results",
                "command": "assetfinder example.com | sort -u",
                "description": "Remove duplicate findings"
            },
            "5": {
                "name": "Filter Domains",
                "command": "assetfinder example.com | grep example.com",
                "description": "Only show matching domains"
            }
        }
    },
    "Screenshots": {
        "EyeWitness": {
            "1": {
                "name": "Single Website",
                "command": "eyewitness --web --single https://example.com -d output",
                "description": "Capture screenshot of a single website"
            },
            "2": {
                "name": "Multiple URLs",
                "command": "eyewitness --web -f urls.txt -d output",
                "description": "Screenshot multiple websites from a file"
            },
            "3": {
                "name": "Full Page",
                "command": "eyewitness --web -f urls.txt -d output --full-page",
                "description": "Capture full-page screenshots"
            },
            "4": {
                "name": "Custom Resolution",
                "command": "eyewitness --web -f urls.txt -d output --resolution 1920x1080",
                "description": "Set custom screenshot resolution"
            },
            "5": {
                "name": "With Timeout",
                "command": "eyewitness --web -f urls.txt -d output --timeout 30",
                "description": "Set custom timeout for loading pages"
            }
        },
        "Aquatone": {
            "1": {
                "name": "Simple Scan",
                "command": "cat hosts.txt | aquatone -out ./aquatone",
                "description": "Basic screenshot capture"
            },
            "2": {
                "name": "Custom Ports",
                "command": "cat hosts.txt | aquatone -ports 80,443,8080 -out ./aquatone",
                "description": "Scan specific ports"
            },
            "3": {
                "name": "Chromium Options",
                "command": "cat hosts.txt | aquatone -chrome-path /path/to/chrome -out ./aquatone",
                "description": "Use custom Chrome path"
            },
            "4": {
                "name": "Threading",
                "command": "cat hosts.txt | aquatone -threads 10 -out ./aquatone",
                "description": "Control concurrent scans"
            },
            "5": {
                "name": "With Proxy",
                "command": "cat hosts.txt | aquatone -proxy http://127.0.0.1:8080 -out ./aquatone",
                "description": "Use proxy for scanning"
            }
        },
        "Gowitness": {
            "1": {
                "name": "Single URL",
                "command": "gowitness single https://example.com",
                "description": "Screenshot single website"
            },
            "2": {
                "name": "File Scan",
                "command": "gowitness file -f urls.txt",
                "description": "Process URLs from file"
            },
            "3": {
                "name": "CIDR Scan",
                "command": "gowitness scan --cidr 192.168.0.0/24",
                "description": "Scan IP range"
            },
            "4": {
                "name": "With Resolution",
                "command": "gowitness single https://example.com --resolution 1920x1080",
                "description": "Custom screenshot size"
            },
            "5": {
                "name": "Chrome Path",
                "command": "gowitness single https://example.com --chrome-path /path/to/chrome",
                "description": "Specify Chrome path"
            }
        },
        "WitnessMe": {
            "1": {
                "name": "Basic Scan",
                "command": "witnessme scan -t https://example.com",
                "description": "Simple screenshot capture"
            },
            "2": {
                "name": "Batch Mode",
                "command": "witnessme scan -f targets.txt",
                "description": "Process multiple targets"
            },
            "3": {
                "name": "Custom Ports",
                "command": "witnessme scan -p 80,443,8080 -f targets.txt",
                "description": "Scan specific ports"
            },
            "4": {
                "name": "Timeout Setting",
                "command": "witnessme scan -f targets.txt --timeout 30",
                "description": "Set page load timeout"
            },
            "5": {
                "name": "Thread Control",
                "command": "witnessme scan -f targets.txt --threads 10",
                "description": "Control parallel processing"
            }
        },
        "HTTPScreenshot": {
            "1": {
                "name": "Quick Scan",
                "command": "httpscreenshot -i targets.txt -p 80,443",
                "description": "Basic screenshot capture"
            },
            "2": {
                "name": "Custom Timeout",
                "command": "httpscreenshot -i targets.txt -t 30",
                "description": "Set timeout value"
            },
            "3": {
                "name": "Auth Scan",
                "command": "httpscreenshot -i targets.txt -a basic -c 'admin:pass'",
                "description": "Use basic auth"
            },
            "4": {
                "name": "Worker Control",
                "command": "httpscreenshot -i targets.txt -w 10",
                "description": "Set worker count"
            },
            "5": {
                "name": "Save Report",
                "command": "httpscreenshot -i targets.txt -r report.html",
                "description": "Generate HTML report"
            }
        }
    },
    "Technologies": {
        "Wappalyzer": {
            "1": {
                "name": "Basic Scan",
                "command": "wappalyzer https://example.com",
                "description": "Identify technologies"
            },
            "2": {
                "name": "Detailed Output",
                "command": "wappalyzer https://example.com --pretty",
                "description": "Formatted detailed output"
            },
            "3": {
                "name": "Batch Analysis",
                "command": "wappalyzer -f urls.txt",
                "description": "Process multiple URLs"
            },
            "4": {
                "name": "JSON Output",
                "command": "wappalyzer https://example.com --json",
                "description": "Output in JSON format"
            },
            "5": {
                "name": "With Categories",
                "command": "wappalyzer https://example.com --categories",
                "description": "Show technology categories"
            }
        },
        "Webanalyze": {
            "1": {
                "name": "Simple Scan",
                "command": "webanalyze -host example.com",
                "description": "Basic technology detection"
            },
            "2": {
                "name": "Update Apps",
                "command": "webanalyze -update",
                "description": "Update technology database"
            },
            "3": {
                "name": "File Input",
                "command": "webanalyze -hosts hosts.txt",
                "description": "Scan multiple hosts"
            },
            "4": {
                "name": "Custom Apps",
                "command": "webanalyze -apps custom_apps.json",
                "description": "Use custom tech definitions"
            },
            "5": {
                "name": "Workers",
                "command": "webanalyze -workers 10 -hosts hosts.txt",
                "description": "Control parallel scanning"
            }
        },
        "WhatWeb": {
            "1": {
                "name": "Quick Scan",
                "command": "whatweb example.com",
                "description": "Basic technology detection"
            },
            "2": {
                "name": "Aggressive Mode",
                "command": "whatweb -a 3 example.com",
                "description": "Detailed aggressive scan"
            },
            "3": {
                "name": "Batch Scan",
                "command": "whatweb -i targets.txt",
                "description": "Process multiple targets"
            },
            "4": {
                "name": "JSON Output",
                "command": "whatweb --log-json=results.json example.com",
                "description": "Save results as JSON"
            },
            "5": {
                "name": "Stealth Mode",
                "command": "whatweb -U='Mozilla/5.0' example.com",
                "description": "Custom user agent"
            }
        },
        "Retire.js": {
            "1": {
                "name": "Basic Scan",
                "command": "retire --path /path/to/js",
                "description": "Check JS dependencies"
            },
            "2": {
                "name": "Node Scan",
                "command": "retire --node",
                "description": "Scan Node.js project"
            },
            "3": {
                "name": "JS Files",
                "command": "retire --js",
                "description": "Scan JavaScript files"
            },
            "4": {
                "name": "Update DB",
                "command": "retire --updatedb",
                "description": "Update vulnerability database"
            },
            "5": {
                "name": "JSON Output",
                "command": "retire --outputformat json --outputpath result.json",
                "description": "Save results as JSON"
            }
        },
        "Httpx": {
            "1": {
                "name": "Simple Probe",
                "command": "httpx -u https://example.com",
                "description": "Basic HTTP probe"
            },
            "2": {
                "name": "Tech Detection",
                "command": "httpx -u https://example.com -tech-detect",
                "description": "Detect technologies"
            },
            "3": {
                "name": "Title Extract",
                "command": "httpx -l urls.txt -title",
                "description": "Extract page titles"
            },
            "4": {
                "name": "Status Code",
                "command": "httpx -l urls.txt -status-code",
                "description": "Show response codes"
            },
            "5": {
                "name": "Full Scan",
                "command": "httpx -l urls.txt -tech-detect -title -status-code -json",
                "description": "Complete technology scan"
            }
        }
    },
    "Content Discovery": {
        "Gau": {
            "1": {
                "name": "Basic Scan",
                "command": "gau example.com",
                "description": "Extract URLs from a website"
            },
            "2": {
                "name": "With Depth",
                "command": "gau -d 2 example.com",
                "description": "Crawl to a specific depth"
            },
            "3": {
                "name": "JSON Output",
                "command": "gau -json example.com",
                "description": "Output results in JSON"
            },
            "4": {
                "name": "Robots.txt Check",
                "command": "gau -robots example.com",
                "description": "Respect robots.txt directives"
            },
            "5": {
                "name": "Exclude Paths",
                "command": "gau -e '/admin','/login' example.com",
                "description": "Exclude certain paths"
            }
        },
        "LinkFinder": {
            "1": {
                "name": "Basic Scan",
                "command": "linkfinder -i example.com",
                "description": "Find URLs within website"
            },
            "2": {
                "name": "With Output",
                "command": "linkfinder -i example.com -o output.txt",
                "description": "Save results to a file"
            },
            "3": {
                "name": "Specific Domains",
                "command": "linkfinder -i example.com -d example.com",
                "description": "Filter only URLs from specified domain"
            },
            "4": {
                "name": "Exclude Patterns",
                "command": "linkfinder -i example.com -e '.*\.jpg','.*\.png'",
                "description": "Exclude image URLs"
            },
            "5": {
                "name": "Recursive Scan",
                "command": "linkfinder -i example.com -r",
                "description": "Recursively crawl website"
            }
        },
        "hakrawler": {
            "1": {
                "name": "Simple Crawl",
                "command": "hakrawler -d example.com",
                "description": "Discover URLs"
            },
            "2": {
                "name": "Output to File",
                "command": "hakrawler -d example.com -o output.txt",
                "description": "Save results to file"
            },
            "3": {
                "name": "Custom User Agent",
                "command": "hakrawler -d example.com -u 'Mozilla/5.0'",
                "description": "Use custom User-Agent"
            },
            "4": {
                "name": "Recursive Crawl",
                "command": "hakrawler -d example.com -r",
                "description": "Recursive crawl with more URLs"
            },
            "5": {
                "name": "HTTP Only",
                "command": "hakrawler -d example.com -http",
                "description": "Only fetch HTTP URLs"
            }
        },
        "Waybackurls": {
            "1": {
                "name": "Basic Scan",
                "command": "waybackurls example.com",
                "description": "Get URLs from Wayback Machine"
            },
            "2": {
                "name": "Unique URLs",
                "command": "waybackurls example.com | sort -u",
                "description": "Get only unique URLs"
            },
            "3": {
                "name": "Filter Extensions",
                "command": "waybackurls example.com | grep '.html'",
                "description": "Filter URLs with specific extensions"
            },
            "4": {
                "name": "With Output",
                "command": "waybackurls example.com > output.txt",
                "description": "Save to a file"
            },
            "5": {
                "name": "Exclude Patterns",
                "command": "waybackurls example.com | grep -v '/search'",
                "description": "Exclude URLs containing patterns"
            }
        },
        "ffuf": {
            "1": {
                "name": "Simple Fuzz",
                "command": "ffuf -u example.com/FUZZ -w wordlist.txt",
                "description": "Fuzz a URL with wordlist"
            },
            "2": {
                "name": "HTTP Method",
                "command": "ffuf -u example.com/FUZZ -w wordlist.txt -H 'GET'",
                "description": "Specify HTTP method"
            },
            "3": {
                "name": "Multiple Fuzzing",
                "command": "ffuf -u 'example.com/FUZZ?param=FUZZ2' -w wordlist.txt -w wordlist2.txt",
                "description": "Fuzz multiple locations"
            },
            "4": {
                "name": "Timeout",
                "command": "ffuf -u example.com/FUZZ -w wordlist.txt -t 10",
                "description": "Set request timeout"
            },
            "5": {
                "name": "Custom Headers",
                "command": "ffuf -u example.com/FUZZ -w wordlist.txt -H 'X-Custom-Header: value'",
                "description": "Include custom headers"
            }
        }
    },
    "Links": {
        "findomian": {
            "1": {
                "name": "Basic Scan",
                "command": "findomain -t example.com",
                "description": "Discover subdomains"
            },
            "2": {
                "name": "With Output",
                "command": "findomain -t example.com -o output.txt",
                "description": "Save results to file"
            },
            "3": {
                "name": "Resolve IPs",
                "command": "findomain -t example.com -r",
                "description": "Resolve subdomain IPs"
            },
            "4": {
                "name": "Monitor Mode",
                "command": "findomain -t example.com -m",
                "description": "Monitor for new subdomains"
            },
            "5": {
                "name": "Full Scan",
                "command": "findomain -t example.com -r -o output.txt",
                "description": "Complete scan with IP resolution and output"
            }
        },
        "shuffler": {
            "1": {
                "name": "Basic Scan",
                "command": "shuffler -i urls.txt",
                "description": "Shuffle the URLs"
            },
            "2": {
                "name": "With Output",
                "command": "shuffler -i urls.txt -o shuffled.txt",
                "description": "Save shuffled URLs to file"
            },
            "3": {
                "name": "Unique URLs",
                "command": "shuffler -i urls.txt -u",
                "description": "Removes duplicate urls"
            },
            "4": {
                "name": "Sort URLs",
                "command": "shuffler -i urls.txt -s",
                "description": "Sort the URLs before shuffling"
            },
            "5": {
                "name": "Shuffle and Save",
                "command": "shuffler -i urls.txt -u -o unique.txt",
                "description": "Removes duplicates and saves to file"
            }
        },
        "filter-urls": {
            "1": {
                "name": "Filter Protocol",
                "command": "cat urls.txt | grep 'https://'",
                "description": "Keep only https URLs"
            },
            "2": {
                "name": "Filter Domain",
                "command": "cat urls.txt | grep 'example.com'",
                "description": "Keep URLs from example.com"
            },
            "3": {
                "name": "Filter Extensions",
                "command": "cat urls.txt | grep '\.html'",
                "description": "Keep URLs ending with .html"
            },
            "4": {
                "name": "Remove Duplicates",
                "command": "cat urls.txt | sort -u",
                "description": "Keep only unique URLs"
            },
            "5": {
                "name": "Advanced Filtering",
                "command": "cat urls.txt | egrep '\.html|\.php'",
                "description": "Keep URLs ending with .html or .php"
            }
        },
        "url-extractor": {
            "1": {
                "name": "Extract from HTML",
                "command": "url-extractor -i index.html",
                "description": "Extract URLs from HTML file"
            },
            "2": {
                "name": "Extract from JSON",
                "command": "url-extractor -i data.json",
                "description": "Extract URLs from JSON file"
            },
            "3": {
                "name": "Extract from Text",
                "command": "url-extractor -i data.txt",
                "description": "Extract URLs from text file"
            },
            "4": {
                "name": "With Output",
                "command": "url-extractor -i index.html -o urls.txt",
                "description": "Save extracted URLs to file"
            },
            "5": {
                "name": "Custom Regex",
                "command": "url-extractor -i index.html -r 'https?://.*'",
                "description": "Use custom regex for URL extraction"
            }
        },
        "xray": {
            "1": {
                "name": "Basic Scan",
                "command": "xray webscan --target example.com",
                "description": "Basic vulnerability scan"
            },
            "2": {
                "name": "With Output",
                "command": "xray webscan --target example.com --html-output output.html",
                "description": "Save results in HTML format"
            },
            "3": {
                "name": "JSON Output",
                "command": "xray webscan --target example.com --json-output output.json",
                "description": "Save results in JSON format"
            },
            "4": {
                "name": "Specific Spider",
                "command": "xray webscan --target example.com --spider=gospider",
                "description": "Use gospider for crawling"
            },
            "5": {
                "name": "Aggressive Scan",
                "command": "xray webscan --target example.com --aggressive",
                "description": "Run aggressive scan"
            }
        }
    },
    "Parameters": {
        "param-miner": {
            "1": {
                "name": "Basic Scan",
                "command": "param-miner -u example.com",
                "description": "Mine parameters from website"
            },
            "2": {
                "name": "With Output",
                "command": "param-miner -u example.com -o output.txt",
                "description": "Save results to file"
            },
            "3": {
                "name": "Custom Headers",
                "command": "param-miner -u example.com -H 'X-Custom-Header: value'",
                "description": "Send custom headers"
            },
            "4": {
                "name": "Exclude Paths",
                "command": "param-miner -u example.com -e '/admin','/login'",
                "description": "Exclude specified paths"
            },
            "5": {
                "name": "Recursive Scan",
                "command": "param-miner -u example.com -r",
                "description": "Recursively crawl website"
            }
        },
        "Dalfox": {
            "1": {
                "name": "Basic Scan",
                "command": "dalfox fuzz -u example.com",
                "description": "Fuzz parameters"
            },
            "2": {
                "name": "With Payload",
                "command": "dalfox fuzz -u example.com --data 'param=value'",
                "description": "Inject custom payloads"
            },
            "3": {
                "name": "SaveOutput",
                "command": "dalfox fuzz -u example.com -o output.txt",
                "description": "Save results to file"
            },
            "4": {
                "name": "Custom Headers",
                "command": "dalfox fuzz -u example.com -H 'X-Custom-Header: value'",
                "description": "Send custom headers"
            },
            "5": {
                "name": "Timeout",
                "command": "dalfox fuzz -u example.com --timeout 30",
                "description": "Set request timeout"
            }
        },
        "Dirsearch": {
            "1": {
                "name": "Basic Scan",
                "command": "dirsearch -u example.com",
                "description": "Discover directories and files"
            },
            "2": {
                "name": "With Extensions",
                "command": "dirsearch -u example.com -e txt,php,html",
                "description": "Specify file extensions"
            },
            "3": {
                "name": "With Output",
                "command": "dirsearch -u example.com -o output.txt",
                "description": "Save results to file"
            },
            "4": {
                "name": "Custom User Agent",
                "command": "dirsearch -u example.com -A 'Mozilla/5.0'",
                "description": "Use custom User-Agent"
            },
            "5": {
                "name": "Threads",
                "command": "dirsearch -u example.com -t 10",
                "description": "Set number of threads"
            }
        },
        "Nuclei": {
            "1": {
                "name": "Basic Scan",
                "command": "nuclei -t templates/ -u example.com",
                "description": "Run vulnerability scan"
            },
            "2": {
                "name": "With Templates",
                "command": "nuclei -t my-templates/ -u example.com",
                "description": "Use custom templates"
            },
            "3": {
                "name": "JSON Output",
                "command": "nuclei -t templates/ -u example.com -json",
                "description": "Save results in JSON format"
            },
            "4": {
                "name": "Verbose Mode",
                "command": "nuclei -t templates/ -u example.com -verbose",
                "description": "Show more details"
            },
            "5": {
                "name": "Rate Limiting",
                "command": "nuclei -t templates/ -u example.com --rate-limit 10",
                "description": "Control scan rate"
            }
        },
        "ffuf": {
            "1": {
                "name": "Simple Fuzz",
                "command": "ffuf -u example.com/FUZZ -w wordlist.txt",
                "description": "Fuzz a URL with wordlist"
            },
            "2": {
                "name": "HTTP Method",
                "command": "ffuf -u example.com/FUZZ -w wordlist.txt -H 'GET'",
                "description": "Specify HTTP method"
            },
            "3": {
                "name": "Multiple Fuzzing",
                "command": "ffuf -u 'example.com/FUZZ?param=FUZZ2' -w wordlist.txt -w wordlist2.txt",
                "description": "Fuzz multiple locations"
            },
            "4": {
                "name": "Timeout",
                "command": "ffuf -u example.com/FUZZ -w wordlist.txt -t 10",
                "description": "Set request timeout"
            },
            "5": {
                "name": "Custom Headers",
                "command": "ffuf -u example.com/FUZZ -w wordlist.txt -H 'X-Custom-Header: value'",
                "description": "Include custom headers"
            }
        },
        "GauPlus": {
            "1": {
                "name": "Basic Scan",
                "command": "gauplus -url example.com",
                "description": "Extract URLs from a target"
            },
            "2": {
                "name": "With Depth",
                "command": "gauplus -url example.com -d 2",
                "description": "Crawl with a maximum depth"
            },
            "3": {
                "name": "With Output",
                "command": "gauplus -url example.com -o output.txt",
                "description": "Save results to file"
            },
            "4": {
                "name": "Custom Headers",
                "command": "gauplus -url example.com -H 'X-Custom-Header: value'",
                "description": "Include custom headers"
            },
            "5": {
                "name": "Threads",
                "command": "gauplus -url example.com -t 10",
                "description": "Control the number of threads"
            }
        }
    },
    "Fuzzing": {
        "ffuf": {
            "1": {
                "name": "Simple Fuzz",
                "command": "ffuf -u example.com/FUZZ -w wordlist.txt",
                "description": "Fuzz a URL with wordlist"
            },
            "2": {
                "name": "HTTP Method",
                "command": "ffuf -u example.com/FUZZ -w wordlist.txt -H 'GET'",
                "description": "Specify HTTP method"
            },
            "3": {
                "name": "Multiple Fuzzing",
                "command": "ffuf -u 'example.com/FUZZ?param=FUZZ2' -w wordlist.txt -w wordlist2.txt",
                "description": "Fuzz multiple locations"
            },
            "4": {
                "name": "Timeout",
                "command": "ffuf -u example.com/FUZZ -w wordlist.txt -t 10",
                "description": "Set request timeout"
            },
            "5": {
                "name": "Custom Headers",
                "command": "ffuf -u example.com/FUZZ -w wordlist.txt -H 'X-Custom-Header: value'",
                "description": "Include custom headers"
            }
        },
        "XSSer": {
            "1": {
                "name": "Basic XSS Scan",
                "command": "xssed -u example.com",
                "description": "Basic XSS scan"
            },
            "2": {
                "name": "Custom Payload",
                "command": "xssed -u example.com -p 'my_xss_payload'",
                "description": "Use custom payload"
            },
            "3": {
                "name": "With Output",
                "command": "xssed -u example.com -o output.txt",
                "description": "Save results to file"
            },
            "4": {
                "name": "Recursive Scan",
                "command": "xssed -u example.com -r",
                "description": "Recursive scan"
            },
            "5": {
                "name": "Thread Control",
                "command": "xssed -u example.com -t 10",
                "description": "Control number of threads"
            }
        },
        "Sqlmap": {
            "1": {
                "name": "Basic Scan",
                "command": "sqlmap -u example.com",
                "description": "Basic SQL injection scan"
            },
            "2": {
                "name": "Specific Parameter",
                "command": "sqlmap -u example.com --data 'param=value'",
                "description": "Target specific parameter"
            },
            "3": {
                "name": "Verbose Mode",
                "command": "sqlmap -u example.com -v 3",
                "description": "Show more details"
            },
            "4": {
                "name": "Risk Level",
                "command": "sqlmap -u example.com --risk=3",
                "description": "Set risk level"
            },
            "5": {
                "name": "Level",
                "command": "sqlmap -u example.com --level=5",
                "description": "Set level of testing"
            }
        },
        "Dirbuster": {
            "1": {
                "name": "Basic Scan",
                "command": "dirbuster -u example.com",
                "description": "Brute force directories"
            },
            "2": {
                "name": "Wordlist",
                "command": "dirbuster -u example.com -w wordlist.txt",
                "description": "Use custom wordlist"
            },
            "3": {
                "name": "Threads",
                "command": "dirbuster -u example.com -t 10",
                "description": "Control number of threads"
            },
            "4": {
                "name": "With Output",
                "command": "dirbuster -u example.com -o output.txt",
                "description": "Save results to file"
            },
            "5": {
                "name": "Extensions",
                "command": "dirbuster -u example.com -e php,html,txt",
                "description": "Specify file extensions"
            }
        },
        "Wfuzz": {
            "1": {
                "name": "Basic Fuzzing",
                "command": "wfuzz -z file,wordlist.txt -H \"User-Agent:Mozilla/5.0\" http://example.com/FUZZ",
                "description": "Basic fuzzing example"
            },
            "2": {
                "name": "Multiple Fuzzing",
                "command": "wfuzz -z file,wordlist.txt -z file,wordlist2.txt http://example.com/FUZZ?param=FUZZ2",
                "description": "Fuzz multiple parameters"
            },
            "3": {
                "name": "HTTP Method",
                "command": "wfuzz -z file,wordlist.txt -m POST http://example.com/FUZZ",
                "description": "Specify HTTP method"
            },
            "4": {
                "name": "Custom Headers",
                "command": "wfuzz -z file,wordlist.txt -H \"X-Custom-Header: value\" http://example.com/FUZZ",
                "description": "Include custom headers"
            },
            "5": {
                "name": "Timeout",
                "command": "wfuzz -z file,wordlist.txt -t 10 http://example.com/FUZZ",
                "description": "Set timeout"
            }
        }
    }
}

def handle_tool_commands(tool_type):
    if tool_type not in TOOL_COMMANDS:
        console.print(f"[red]No tools configured for {tool_type}[/red]")
        return

    while True:
        console.print(f"\n[bold cyan]Available {tool_type} Tools:[/bold cyan]")
        tools = list(TOOL_COMMANDS[tool_type].keys())
        for i, tool in enumerate(tools, 1):
            console.print(f"{i}. {tool}")

        tool_choice = Prompt.ask(
            "\n[yellow]Select a tool number or type 'back'[/yellow]",
            choices=[str(i) for i in range(1, len(tools) + 1)] + ["back"],
            default="back"
        )

        if tool_choice == "back":
            break

        selected_tool = tools[int(tool_choice) - 1]
        display_tool_commands(tool_type, selected_tool)

def display_tool_commands(tool_type, tool_name):
    commands = TOOL_COMMANDS[tool_type][tool_name]

    while True:
        console.print(f"\n[bold cyan]━━━ {tool_name} Commands ━━━[/bold cyan]")
        for cmd_id, cmd_info in commands.items():
            console.print(f"\n[yellow]{cmd_id}[/yellow]: {cmd_info['name']}")
            console.print(f"[dim]Description: {cmd_info['description']}[/dim]")
            console.print(f"[blue]Command: {cmd_info['command']}[/blue]")
            console.print("─" * 50)

        cmd_choice = Prompt.ask(
            "\n[yellow]Select a command number to copy, or type 'back'[/yellow]",
            choices=list(commands.keys()) + ["back"],
            default="back"
        )

        if cmd_choice == "back":
            break

        command = commands[cmd_choice]["command"]
        execute_command(command)