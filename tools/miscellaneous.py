
from rich.console import Console
from rich.prompt import Prompt
from BugBountyToolsAssistant.utils.command_executor import execute_command

console = Console()

TOOL_COMMANDS = {
    "Passwords": {
        "THC-Hydra": {
            "1": {
                "name": "HTTP Basic Auth",
                "command": "hydra -l admin -P wordlist.txt example.com http-get /admin",
                "description": "Brute force HTTP basic auth"
            },
            "2": {
                "name": "SSH Login",
                "command": "hydra -L users.txt -P passwords.txt ssh://example.com",
                "description": "Brute force SSH login"
            },
            "3": {
                "name": "FTP Access",
                "command": "hydra -l ftpuser -P wordlist.txt ftp://example.com",
                "description": "Brute force FTP server"
            },
            "4": {
                "name": "POST Form",
                "command": "hydra -l admin -P wordlist.txt example.com http-post-form '/login.php:username=^USER^&password=^PASS^:F=Invalid'",
                "description": "Attack web form with POST"
            },
            "5": {
                "name": "MySQL DB",
                "command": "hydra -l root -P passwords.txt example.com mysql",
                "description": "Brute force MySQL database"
            }
        },
        "Changeme": {
            "1": {
                "name": "Basic Scan",
                "command": "changeme example.com",
                "description": "Scan for default credentials"
            },
            "2": {
                "name": "Specific Port",
                "command": "changeme example.com:8080",
                "description": "Scan specific port"
            },
            "3": {
                "name": "Custom Name",
                "command": "changeme example.com -n 'Corporate Router'",
                "description": "Specify device name"
            },
            "4": {
                "name": "With Output",
                "command": "changeme example.com --output results.csv",
                "description": "Save results to CSV"
            },
            "5": {
                "name": "Specific Protocol",
                "command": "changeme example.com --protocols http",
                "description": "Only check HTTP services"
            }
        },
        "Patator": {
            "1": {
                "name": "FTP Attack",
                "command": "patator ftp_login host=example.com user=root password=FILE0 0=passwords.txt",
                "description": "Brute force FTP login"
            },
            "2": {
                "name": "SSH Attack",
                "command": "patator ssh_login host=example.com user=admin password=FILE0 0=passwords.txt",
                "description": "Brute force SSH login"
            },
            "3": {
                "name": "HTTP Basic Auth",
                "command": "patator http_fuzz url=http://example.com/admin method=GET auth_type=basic user_pass=admin:FILE0 0=passwords.txt",
                "description": "Brute force HTTP basic auth"
            },
            "4": {
                "name": "MySQL Attack",
                "command": "patator mysql_login host=example.com user=root password=FILE0 0=passwords.txt",
                "description": "Brute force MySQL login"
            },
            "5": {
                "name": "DNS Forward",
                "command": "patator dns_forward name=FILE0.example.com 0=subdomains.txt",
                "description": "DNS forward lookup"
            }
        },
        "BruteX": {
            "1": {
                "name": "Full Scan",
                "command": "brutex example.com",
                "description": "Full service brute force"
            },
            "2": {
                "name": "With Wordlist",
                "command": "brutex -p passwords.txt example.com",
                "description": "Use custom password list"
            },
            "3": {
                "name": "With Userlist",
                "command": "brutex -u users.txt -p passwords.txt example.com",
                "description": "Use custom user and password list"
            },
            "4": {
                "name": "Target File",
                "command": "brutex -f targets.txt",
                "description": "Brute force targets from file"
            },
            "5": {
                "name": "Service Specific",
                "command": "brutex -s ssh,ftp example.com",
                "description": "Only brute force specific services"
            }
        },
        "DefaultCreds-cheat-sheet": {
            "1": {
                "name": "Search Routers",
                "command": "default-creds-cheat-sheet search router",
                "description": "Search for router credentials"
            },
            "2": {
                "name": "Search By Vendor",
                "command": "default-creds-cheat-sheet search cisco",
                "description": "Search by vendor name"
            },
            "3": {
                "name": "Search By Model",
                "command": "default-creds-cheat-sheet search 'WRT54G'",
                "description": "Search by device model"
            },
            "4": {
                "name": "List All",
                "command": "default-creds-cheat-sheet list",
                "description": "List all available credentials"
            },
            "5": {
                "name": "Export Results",
                "command": "default-creds-cheat-sheet search cisco -o cisco-creds.txt",
                "description": "Save results to file"
            }
        }
    },
    "Secrets": {
        "Git-secrets": {
            "1": {
                "name": "Scan Repository",
                "command": "git-secrets --scan",
                "description": "Scan Git repository for secrets"
            },
            "2": {
                "name": "Scan Directory",
                "command": "git-secrets --scan /path/to/directory",
                "description": "Scan a specific directory for secrets"
            },
            "3": {
                "name": "Register AWS",
                "command": "git-secrets --register-aws",
                "description": "Add AWS patterns to search for"
            },
            "4": {
                "name": "Add Pattern",
                "command": "git-secrets --add 'api_key\\s*=\\s*.+'",
                "description": "Add custom regex pattern"
            },
            "5": {
                "name": "Install Hooks",
                "command": "git-secrets --install",
                "description": "Install Git hooks to prevent commits with secrets"
            }
        },
        "Gitleaks": {
            "1": {
                "name": "Basic Scan",
                "command": "gitleaks detect",
                "description": "Scan current repository"
            },
            "2": {
                "name": "Scan Path",
                "command": "gitleaks detect --source /path/to/code",
                "description": "Scan specific directory"
            },
            "3": {
                "name": "Scan Repository",
                "command": "gitleaks detect --repo=https://github.com/user/repo",
                "description": "Scan remote repository"
            },
            "4": {
                "name": "Output Format",
                "command": "gitleaks detect --report-format json --report-path leaks.json",
                "description": "Save results as JSON"
            },
            "5": {
                "name": "Custom Rules",
                "command": "gitleaks detect --config-path rules.toml",
                "description": "Use custom detection rules"
            }
        },
        "TruffleHog": {
            "1": {
                "name": "Scan Repository",
                "command": "trufflehog git https://github.com/user/repo",
                "description": "Scan Git repository"
            },
            "2": {
                "name": "Scan Directory",
                "command": "trufflehog filesystem /path/to/code",
                "description": "Scan local files"
            },
            "3": {
                "name": "Specific Branch",
                "command": "trufflehog git https://github.com/user/repo --branch main",
                "description": "Scan specific branch"
            },
            "4": {
                "name": "JSON Output",
                "command": "trufflehog git https://github.com/user/repo --json",
                "description": "Output results as JSON"
            },
            "5": {
                "name": "Custom Rules",
                "command": "trufflehog git https://github.com/user/repo --rules rules.json",
                "description": "Use custom detection rules"
            }
        },
        "Talisman": {
            "1": {
                "name": "Scan Repository",
                "command": "talisman --scan",
                "description": "Scan current repository"
            },
            "2": {
                "name": "Pre-commit Check",
                "command": "talisman --githook pre-commit",
                "description": "Run as pre-commit hook"
            },
            "3": {
                "name": "Custom Patterns",
                "command": "talisman --pattern 'apikey.*'",
                "description": "Use custom detection pattern"
            },
            "4": {
                "name": "Detailed Results",
                "command": "talisman --scan --verbose",
                "description": "Show detailed results"
            },
            "5": {
                "name": "Checksum Calculate",
                "command": "talisman --checksum sensitive_file.txt",
                "description": "Generate checksum for ignoring files"
            }
        },
        "GitGot": {
            "1": {
                "name": "Basic Search",
                "command": "gitgot -q api_key",
                "description": "Search repositories for API keys"
            },
            "2": {
                "name": "Multiple Terms",
                "command": "gitgot -q 'password,secret,token'",
                "description": "Search for multiple terms"
            },
            "3": {
                "name": "GitHub Search",
                "command": "gitgot -t github -q 'api_key'",
                "description": "Search GitHub specifically"
            },
            "4": {
                "name": "Output File",
                "command": "gitgot -q 'password' -o results.txt",
                "description": "Save results to file"
            },
            "5": {
                "name": "Regular Expression",
                "command": "gitgot -q 'key=[A-Za-z0-9]{32}'",
                "description": "Search using regex pattern"
            }
        }
    },
    "Git": {
        "GitTools": {
            "1": {
                "name": "Dumper",
                "command": "gittools-dumper http://example.com/.git/ output-dir",
                "description": "Dump .git repository"
            },
            "2": {
                "name": "Extractor",
                "command": "gittools-extractor output-dir extracted-dir",
                "description": "Extract repository files"
            },
            "3": {
                "name": "Finder",
                "command": "gittools-finder -i targets.txt -o results.txt",
                "description": "Find .git repositories"
            },
            "4": {
                "name": "Finder Domain",
                "command": "gittools-finder -u example.com -o results.txt",
                "description": "Find repositories on domain"
            },
            "5": {
                "name": "Full Process",
                "command": "gittools-dumper http://example.com/.git/ dump && gittools-extractor dump extracted",
                "description": "Dump and extract in one command"
            }
        },
        "Gitjacker": {
            "1": {
                "name": "Basic Scan",
                "command": "gitjacker -u http://example.com",
                "description": "Scan for exposed Git repositories"
            },
            "2": {
                "name": "With Output",
                "command": "gitjacker -u http://example.com -o output-dir",
                "description": "Save discovered repositories"
            },
            "3": {
                "name": "Multiple Targets",
                "command": "gitjacker -f targets.txt",
                "description": "Scan multiple targets"
            },
            "4": {
                "name": "Quiet Mode",
                "command": "gitjacker -u http://example.com -q",
                "description": "Minimal output"
            },
            "5": {
                "name": "Depth Setting",
                "command": "gitjacker -u http://example.com -d 3",
                "description": "Set recursion depth"
            }
        },
        "Git-dumper": {
            "1": {
                "name": "Basic Dump",
                "command": "git-dumper http://example.com/.git/ output-dir",
                "description": "Dump Git repository"
            },
            "2": {
                "name": "With Threads",
                "command": "git-dumper -t 10 http://example.com/.git/ output-dir",
                "description": "Use multiple threads"
            },
            "3": {
                "name": "With Auth",
                "command": "git-dumper -u username -p password http://example.com/.git/ output-dir",
                "description": "Use authentication"
            },
            "4": {
                "name": "Proxy Setting",
                "command": "git-dumper --proxy http://proxy:8080 http://example.com/.git/ output-dir",
                "description": "Use proxy server"
            },
            "5": {
                "name": "Custom Agent",
                "command": "git-dumper -a 'Mozilla/5.0' http://example.com/.git/ output-dir",
                "description": "Set custom User-Agent"
            }
        },
        "GitHunter": {
            "1": {
                "name": "Organization Scan",
                "command": "githunter -o organization",
                "description": "Scan organization repositories"
            },
            "2": {
                "name": "User Scan",
                "command": "githunter -u username",
                "description": "Scan user repositories"
            },
            "3": {
                "name": "Custom Patterns",
                "command": "githunter -u username -p patterns.txt",
                "description": "Use custom patterns file"
            },
            "4": {
                "name": "Output Format",
                "command": "githunter -u username -f json -o results.json",
                "description": "Save as JSON"
            },
            "5": {
                "name": "Token Auth",
                "command": "githunter -u username -t 'github_token'",
                "description": "Use GitHub API token"
            }
        },
        "Dvcs-ripper": {
            "1": {
                "name": "Rip Git",
                "command": "rip-git.pl -v -u http://example.com/.git/",
                "description": "Download exposed Git repository"
            },
            "2": {
                "name": "Rip SVN",
                "command": "rip-svn.pl -v -u http://example.com/.svn/",
                "description": "Download exposed SVN repository"
            },
            "3": {
                "name": "Rip CVS",
                "command": "rip-cvs.pl -v -u http://example.com/CVS/",
                "description": "Download exposed CVS repository"
            },
            "4": {
                "name": "With Proxy",
                "command": "rip-git.pl -v -u http://example.com/.git/ -p http://proxy:8080",
                "description": "Use proxy server"
            },
            "5": {
                "name": "Aggressive Mode",
                "command": "rip-git.pl -v -u http://example.com/.git/ -a",
                "description": "Use aggressive download mode"
            }
        }
    },
    "Buckets": {
        "S3Scanner": {
            "1": {
                "name": "Basic Scan",
                "command": "s3scanner scan -bucket-name example-bucket",
                "description": "Scan a single S3 bucket"
            },
            "2": {
                "name": "Multiple Buckets",
                "command": "s3scanner scan -bucket-list buckets.txt",
                "description": "Scan multiple buckets from file"
            },
            "3": {
                "name": "Domain Keywords",
                "command": "s3scanner find -keywords 'company,project,backup'",
                "description": "Find buckets based on keywords"
            },
            "4": {
                "name": "Check Permissions",
                "command": "s3scanner permissions -bucket-name example-bucket",
                "description": "Check bucket permissions"
            },
            "5": {
                "name": "Output Results",
                "command": "s3scanner scan -bucket-list buckets.txt -output results.csv",
                "description": "Save results to CSV file"
            }
        },
        "AWSBucketDump": {
            "1": {
                "name": "Search Keywords",
                "command": "awsbucketdump -s 'keyword1,keyword2' -g",
                "description": "Search for keywords in buckets"
            },
            "2": {
                "name": "With Regions",
                "command": "awsbucketdump -s 'keyword' -r 'us-east-1,us-west-2'",
                "description": "Search in specific regions"
            },
            "3": {
                "name": "Bucket Names",
                "command": "awsbucketdump -l bucket-names.txt",
                "description": "Check list of bucket names"
            },
            "4": {
                "name": "Download Files",
                "command": "awsbucketdump -l bucket-names.txt -D",
                "description": "Download bucket contents"
            },
            "5": {
                "name": "Custom Pattern",
                "command": "awsbucketdump -l bucket-names.txt -d 'password|key|secret'",
                "description": "Search for specific patterns"
            }
        },
        "CloudScraper": {
            "1": {
                "name": "Domain Search",
                "command": "cloudscraper -d example.com",
                "description": "Find buckets related to domain"
            },
            "2": {
                "name": "Keywords Search",
                "command": "cloudscraper -k 'keyword1,keyword2'",
                "description": "Search for buckets by keywords"
            },
            "3": {
                "name": "Check Access",
                "command": "cloudscraper -d example.com -c",
                "description": "Check bucket access permissions"
            },
            "4": {
                "name": "Output Format",
                "command": "cloudscraper -d example.com -o json -f results.json",
                "description": "Save results as JSON"
            },
            "5": {
                "name": "Multiple Domains",
                "command": "cloudscraper -l domains.txt",
                "description": "Scan multiple domains from file"
            }
        },
        "Festin": {
            "1": {
                "name": "Simple Scan",
                "command": "festin example.com",
                "description": "Scan domain for S3 buckets"
            },
            "2": {
                "name": "Deep Scan",
                "command": "festin example.com --deep",
                "description": "Perform deep scanning"
            },
            "3": {
                "name": "Concurrency",
                "command": "festin example.com -c 10",
                "description": "Set concurrency level"
            },
            "4": {
                "name": "Output File",
                "command": "festin example.com -o results.json",
                "description": "Save results to file"
            },
            "5": {
                "name": "Include Subdomains",
                "command": "festin example.com --include-subdomains",
                "description": "Also scan subdomains"
            }
        },
        "S3tk": {
            "1": {
                "name": "Check Buckets",
                "command": "s3tk check",
                "description": "Check bucket security"
            },
            "2": {
                "name": "Dump Policy",
                "command": "s3tk dump example-bucket",
                "description": "Dump bucket policy"
            },
            "3": {
                "name": "Configure ACL",
                "command": "s3tk configure example-bucket --acl private",
                "description": "Configure bucket ACL"
            },
            "4": {
                "name": "Enable Logging",
                "command": "s3tk configure example-bucket --logging",
                "description": "Enable bucket logging"
            },
            "5": {
                "name": "Encrypt Objects",
                "command": "s3tk configure example-bucket --encryption",
                "description": "Enable default encryption"
            }
        }
    },
    "CMS": {
        "WPScan": {
            "1": {
                "name": "Basic Scan",
                "command": "wpscan --url https://example.com",
                "description": "Basic WordPress scan"
            },
            "2": {
                "name": "Enumerate Users",
                "command": "wpscan --url https://example.com --enumerate u",
                "description": "Enumerate WordPress users"
            },
            "3": {
                "name": "Enumerate Plugins",
                "command": "wpscan --url https://example.com --enumerate p",
                "description": "Enumerate plugins"
            },
            "4": {
                "name": "Password Attack",
                "command": "wpscan --url https://example.com --passwords wordlist.txt --usernames admin",
                "description": "Brute force login"
            },
            "5": {
                "name": "API Token",
                "command": "wpscan --url https://example.com --api-token YOUR_TOKEN",
                "description": "Use API for vulnerability data"
            }
        },
        "Joomscan": {
            "1": {
                "name": "Basic Scan",
                "command": "joomscan -u https://example.com",
                "description": "Basic Joomla scan"
            },
            "2": {
                "name": "With Cookie",
                "command": "joomscan -u https://example.com --cookie 'session=value'",
                "description": "Scan with cookies"
            },
            "3": {
                "name": "Components",
                "command": "joomscan -u https://example.com --components",
                "description": "Enumerate components"
            },
            "4": {
                "name": "Full Report",
                "command": "joomscan -u https://example.com --full-report",
                "description": "Generate detailed report"
            },
            "5": {
                "name": "Random Agent",
                "command": "joomscan -u https://example.com --random-agent",
                "description": "Use random User-Agent"
            }
        },
        "CMSmap": {
            "1": {
                "name": "Basic Scan",
                "command": "cmsmap https://example.com",
                "description": "Scan for CMS vulnerabilities"
            },
            "2": {
                "name": "WordPress Focus",
                "command": "cmsmap https://example.com -f W",
                "description": "WordPress focused scan"
            },
            "3": {
                "name": "Joomla Focus",
                "command": "cmsmap https://example.com -f J",
                "description": "Joomla focused scan"
            },
            "4": {
                "name": "Drupal Focus",
                "command": "cmsmap https://example.com -f D",
                "description": "Drupal focused scan"
            },
            "5": {
                "name": "Brute Force",
                "command": "cmsmap https://example.com -a -u admin -w passwords.txt",
                "description": "Attempt login brute force"
            }
        },
        "Pyfiscan": {
            "1": {
                "name": "Basic Scan",
                "command": "pyfiscan -u https://example.com",
                "description": "Scan for vulnerabilities"
            },
            "2": {
                "name": "Directory Scan",
                "command": "pyfiscan -d /var/www/html",
                "description": "Scan local directory"
            },
            "3": {
                "name": "Output File",
                "command": "pyfiscan -u https://example.com -o results.txt",
                "description": "Save results to file"
            },
            "4": {
                "name": "Multiple URLs",
                "command": "pyfiscan -f urls.txt",
                "description": "Scan URLs from file"
            },
            "5": {
                "name": "Verbose Mode",
                "command": "pyfiscan -u https://example.com -v",
                "description": "Show detailed output"
            }
        },
        "AEMHacker": {
            "1": {
                "name": "Comprehensive Scan",
                "command": "aemhacker -u https://example.com",
                "description": "Full Adobe Experience Manager scan"
            },
            "2": {
                "name": "Default Paths",
                "command": "aemhacker -u https://example.com --default-paths",
                "description": "Check default paths"
            },
            "3": {
                "name": "Check Credentials",
                "command": "aemhacker -u https://example.com --creds",
                "description": "Test default credentials"
            },
            "4": {
                "name": "Content Finder",
                "command": "aemhacker -u https://example.com --content-finder",
                "description": "Test content finder access"
            },
            "5": {
                "name": "GQLi Test",
                "command": "aemhacker -u https://example.com --gqli",
                "description": "Test GraphQL injection"
            }
        }
    },
    "JSON Web Token": {
        "JWT_Tool": {
            "1": {
                "name": "Token Analysis",
                "command": "jwt_tool <token>",
                "description": "Analyze JWT structure"
            },
            "2": {
                "name": "Signature Bypass",
                "command": "jwt_tool <token> -X a",
                "description": "Attempt signature bypass"
            },
            "3": {
                "name": "Brute Force",
                "command": "jwt_tool <token> -C -d wordlist.txt",
                "description": "Crack signature key"
            },
            "4": {
                "name": "Exploitation",
                "command": "jwt_tool <token> -T",
                "description": "Test various exploits"
            },
            "5": {
                "name": "Tamper Mode",
                "command": "jwt_tool <token> -I -pc name -pv admin",
                "description": "Tamper token payload"
            }
        },
        "C-JWT-Cracker": {
            "1": {
                "name": "Basic Crack",
                "command": "c-jwt-cracker <token>",
                "description": "Brute force JWT signature"
            },
            "2": {
                "name": "With Alphabet",
                "command": "c-jwt-cracker <token> -a abcdefghijklmnopqrstuvwxyz",
                "description": "Define character set"
            },
            "3": {
                "name": "Max Length",
                "command": "c-jwt-cracker <token> -l 6",
                "description": "Set maximum length"
            },
            "4": {
                "name": "Thread Count",
                "command": "c-jwt-cracker <token> -t 8",
                "description": "Set thread count"
            },
            "5": {
                "name": "Verbose Mode",
                "command": "c-jwt-cracker <token> -v",
                "description": "Show detailed output"
            }
        },
        "JWT-Heartbreaker": {
            "1": {
                "name": "Basic Test",
                "command": "jwt-heartbreaker -t <token>",
                "description": "Test JWT vulnerabilities"
            },
            "2": {
                "name": "With Wordlist",
                "command": "jwt-heartbreaker -t <token> -w wordlist.txt",
                "description": "Brute force with dictionary"
            },
            "3": {
                "name": "None Algorithm",
                "command": "jwt-heartbreaker -t <token> --none",
                "description": "Test 'none' algorithm attack"
            },
            "4": {
                "name": "Key Confusion",
                "command": "jwt-heartbreaker -t <token> --confusion",
                "description": "Test algorithm confusion"
            },
            "5": {
                "name": "Output File",
                "command": "jwt-heartbreaker -t <token> -o results.txt",
                "description": "Save results to file"
            }
        },
        "JWTEar": {
            "1": {
                "name": "Basic Scan",
                "command": "jwtear -t <token>",
                "description": "Scan JWT for vulnerabilities"
            },
            "2": {
                "name": "Key Crack",
                "command": "jwtear -t <token> -k -w wordlist.txt",
                "description": "Brute force secret key"
            },
            "3": {
                "name": "Exploit Mode",
                "command": "jwtear -t <token> -x",
                "description": "Run exploits against token"
            },
            "4": {
                "name": "Header Injection",
                "command": "jwtear -t <token> -i 'alg:none'",
                "description": "Inject header parameters"
            },
            "5": {
                "name": "JSON Output",
                "command": "jwtear -t <token> -o json -f output.json",
                "description": "Save results as JSON"
            }
        },
        "JWT-Hack": {
            "1": {
                "name": "Token Analysis",
                "command": "jwt-hack <token>",
                "description": "Analyze JWT token"
            },
            "2": {
                "name": "Brute Force",
                "command": "jwt-hack <token> --brute-force -w wordlist.txt",
                "description": "Brute force secret key"
            },
            "3": {
                "name": "Embedded Key",
                "command": "jwt-hack <token> --embedded-key",
                "description": "Extract embedded key"
            },
            "4": {
                "name": "KID Injection",
                "command": "jwt-hack <token> --kid-injection",
                "description": "Test KID parameter injection"
            },
            "5": {
                "name": "JWT Forgery",
                "command": "jwt-hack <token> --forge -p 'role:admin'",
                "description": "Forge new token"
            }
        }
    },
    "postMessage": {
        "PostMessage-tracker": {
            "1": {
                "name": "Monitor URL",
                "command": "postmessage-tracker -u https://example.com",
                "description": "Monitor postMessage events"
            },
            "2": {
                "name": "Log Events",
                "command": "postmessage-tracker -u https://example.com -l events.log",
                "description": "Log events to file"
            },
            "3": {
                "name": "With Origin",
                "command": "postmessage-tracker -u https://example.com -o 'https://attacker.com'",
                "description": "Set Origin header"
            },
            "4": {
                "name": "Verbose Mode",
                "command": "postmessage-tracker -u https://example.com -v",
                "description": "Show detailed output"
            },
            "5": {
                "name": "Filter Events",
                "command": "postmessage-tracker -u https://example.com -f 'token,password,key'",
                "description": "Filter specific events"
            }
        },
        "PostMessage_Fuzz_Tool": {
            "1": {
                "name": "Basic Fuzzing",
                "command": "postmessage-fuzz -u https://example.com",
                "description": "Fuzz postMessage handlers"
            },
            "2": {
                "name": "Custom Payload",
                "command": "postmessage-fuzz -u https://example.com -p 'payload.json'",
                "description": "Use custom payloads"
            },
            "3": {
                "name": "Origin Test",
                "command": "postmessage-fuzz -u https://example.com --test-origins",
                "description": "Test origin validation"
            },
            "4": {
                "name": "Data Types",
                "command": "postmessage-fuzz -u https://example.com --data-types",
                "description": "Test various data types"
            },
            "5": {
                "name": "Report Generate",
                "command": "postmessage-fuzz -u https://example.com -r report.html",
                "description": "Generate HTML report"
            }
        }
    },
    "Subdomain Takeover": {
        "Subjack": {
            "1": {
                "name": "Basic Scan",
                "command": "subjack -w subdomains.txt -t 100 -timeout 30 -o results.txt -ssl",
                "description": "Check subdomain takeover"
            },
            "2": {
                "name": "With Config",
                "command": "subjack -w subdomains.txt -c config.json -o results.txt",
                "description": "Use custom configuration"
            },
            "3": {
                "name": "Specific Service",
                "command": "subjack -w subdomains.txt -a -o results.txt",
                "description": "Show all results"
            },
            "4": {
                "name": "Verify Mode",
                "command": "subjack -w subdomains.txt -v -o results.txt",
                "description": "Verify findings"
            },
            "5": {
                "name": "Domain Scan",
                "command": "subjack -d example.com -o results.txt",
                "description": "Scan single domain"
            }
        },
        "SubOver": {
            "1": {
                "name": "Basic Scan",
                "command": "subover -l subdomains.txt",
                "description": "Check subdomain takeover"
            },
            "2": {
                "name": "Thread Control",
                "command": "subover -l subdomains.txt -t 20",
                "description": "Set thread count"
            },
            "3": {
                "name": "Timeout",
                "command": "subover -l subdomains.txt -timeout 30",
                "description": "Set request timeout"
            },
            "4": {
                "name": "With Output",
                "command": "subover -l subdomains.txt -o results.txt",
                "description": "Save results to file"
            },
            "5": {
                "name": "Specific Provider",
                "command": "subover -l subdomains.txt -p github",
                "description": "Check specific provider"
            }
        },
        "AutoSubTakeover": {
            "1": {
                "name": "Basic Scan",
                "command": "autosubtakeover -d example.com",
                "description": "Scan domain for takeover"
            },
            "2": {
                "name": "From File",
                "command": "autosubtakeover -f subdomains.txt",
                "description": "Scan from file"
            },
            "3": {
                "name": "All Checks",
                "command": "autosubtakeover -d example.com -a",
                "description": "Run all checks"
            },
            "4": {
                "name": "With Output",
                "command": "autosubtakeover -d example.com -o results.txt",
                "description": "Save results to file"
            },
            "5": {
                "name": "JSON Format",
                "command": "autosubtakeover -d example.com -j -o results.json",
                "description": "Output as JSON"
            }
        },
        "NSBrute": {
            "1": {
                "name": "Basic Scan",
                "command": "nsbrute -d example.com",
                "description": "Check nameserver takeover"
            },
            "2": {
                "name": "Wordlist",
                "command": "nsbrute -d example.com -w wordlist.txt",
                "description": "Use custom subdomain list"
            },
            "3": {
                "name": "Threads",
                "command": "nsbrute -d example.com -t 20",
                "description": "Set thread count"
            },
            "4": {
                "name": "Output File",
                "command": "nsbrute -d example.com -o results.txt",
                "description": "Save results to file"
            },
            "5": {
                "name": "Verbose Mode",
                "command": "nsbrute -d example.com -v",
                "description": "Show detailed output"
            }
        },
        "TKO-Subs": {
            "1": {
                "name": "Basic Scan",
                "command": "tko-subs -domains=subdomains.txt -output=results.txt",
                "description": "Check subdomain takeover"
            },
            "2": {
                "name": "Concurrency",
                "command": "tko-subs -domains=subdomains.txt -concurrency=20 -output=results.txt",
                "description": "Set concurrent requests"
            },
            "3": {
                "name": "Provider Scan",
                "command": "tko-subs -domains=subdomains.txt -providers=all -output=results.txt",
                "description": "Scan all providers"
            },
            "4": {
                "name": "Specific Providers",
                "command": "tko-subs -domains=subdomains.txt -providers=s3,github,heroku",
                "description": "Scan specific providers"
            },
            "5": {
                "name": "JSON Output",
                "command": "tko-subs -domains=subdomains.txt -format=json -output=results.json",
                "description": "Save as JSON"
            }
        }
    },
    "Vulnerability Scanners": {
        "Nuclei": {
            "1": {
                "name": "Basic Scan",
                "command": "nuclei -u https://example.com",
                "description": "Basic vulnerability scan"
            },
            "2": {
                "name": "Template Categories",
                "command": "nuclei -u https://example.com -t cves,exposures,vulnerabilities",
                "description": "Scan specific categories"
            },
            "3": {
                "name": "Severity Level",
                "command": "nuclei -u https://example.com -severity high,critical",
                "description": "Filter by severity"
            },
            "4": {
                "name": "Multiple Targets",
                "command": "nuclei -l urls.txt",
                "description": "Scan from file"
            },
            "5": {
                "name": "Output Format",
                "command": "nuclei -u https://example.com -o results.json -json",
                "description": "Save as JSON"
            }
        },
        "Sn1per": {
            "1": {
                "name": "Basic Scan",
                "command": "sniper -t example.com",
                "description": "Basic reconnaissance"
            },
            "2": {
                "name": "Stealth Mode",
                "command": "sniper -t example.com -m stealth",
                "description": "Stealthy footprinting"
            },
            "3": {
                "name": "Full Scan",
                "command": "sniper -t example.com -m normal",
                "description": "Complete vulnerability scan"
            },
            "4": {
                "name": "Web Mode",
                "command": "sniper -t example.com -m web",
                "description": "Web vulnerabilities only"
            },
            "5": {
                "name": "Report Generation",
                "command": "sniper -t example.com -w report",
                "description": "Generate full report"
            }
        },
        "Metasploit": {
            "1": {
                "name": "Start Console",
                "command": "msfconsole",
                "description": "Start Metasploit Framework"
            },
            "2": {
                "name": "Basic Scan",
                "command": "msfconsole -q -x 'db_nmap -sV target.com; exit'",
                "description": "Run Nmap scan"
            },
            "3": {
                "name": "Vulnerability Scan",
                "command": "msfconsole -q -x 'use auxiliary/scanner/http/dir_scanner; set RHOSTS target.com; run; exit'",
                "description": "Run directory scanner"
            },
            "4": {
                "name": "Exploit Search",
                "command": "msfconsole -q -x 'search type:exploit platform:windows; exit'",
                "description": "Search for exploits"
            },
            "5": {
                "name": "Workspace Setup",
                "command": "msfconsole -q -x 'workspace -a project; db_import scan.xml; hosts; exit'",
                "description": "Import scan results"
            }
        },
        "Nikto": {
            "1": {
                "name": "Basic Scan",
                "command": "nikto -h https://example.com",
                "description": "Basic web vulnerability scan"
            },
            "2": {
                "name": "Comprehensive",
                "command": "nikto -h https://example.com -Tuning 123bde",
                "description": "Complete scan with tuning"
            },
            "3": {
                "name": "With Auth",
                "command": "nikto -h https://example.com -id username:password",
                "description": "Authenticated scan"
            },
            "4": {
                "name": "Output Format",
                "command": "nikto -h https://example.com -o report.html -Format html",
                "description": "Generate HTML report"
            },
            "5": {
                "name": "Specific Tests",
                "command": "nikto -h https://example.com -Tuning 9",
                "description": "Run SQL injection tests"
            }
        },
        "Arachni": {
            "1": {
                "name": "Basic Scan",
                "command": "arachni https://example.com",
                "description": "Basic web vulnerability scan"
            },
            "2": {
                "name": "With Scope",
                "command": "arachni https://example.com --scope-include-pattern 'products'",
                "description": "Limit scan scope"
            },
            "3": {
                "name": "Authentication",
                "command": "arachni https://example.com --plugin=autologin:username=user,password=pass,url=https://example.com/login",
                "description": "Authenticated scan"
            },
            "4": {
                "name": "Custom Checks",
                "command": "arachni https://example.com --checks=xss,sql_injection",
                "description": "Run specific checks"
            },
            "5": {
                "name": "Report Generation",
                "command": "arachni_reporter report.afr --reporter=html:outfile=report.html",
                "description": "Generate HTML report"
            }
        }
    },
    "Useful": {
        "Anew": {
            "1": {
                "name": "Basic Use",
                "command": "cat new_items.txt | anew existing_items.txt",
                "description": "Add new lines to file"
            },
            "2": {
                "name": "Input Mode",
                "command": "cat data.txt | anew -q results.txt",
                "description": "Quiet mode (no output)"
            },
            "3": {
                "name": "Find New",
                "command": "cat new_data.txt | anew existing_data.txt > only_new_items.txt",
                "description": "Filter only new items"
            },
            "4": {
                "name": "Count New",
                "command": "cat new_data.txt | anew -c existing_data.txt",
                "description": "Show count of new items"
            },
            "5": {
                "name": "Pipe Commands",
                "command": "subfinder -d example.com | anew subdomains.txt",
                "description": "Add new subdomains to file"
            }
        },
        "Gf": {
            "1": {
                "name": "Find URLs",
                "command": "cat urls.txt | gf xss",
                "description": "Find potential XSS URLs"
            },
            "2": {
                "name": "SQL Injection",
                "command": "cat urls.txt | gf sqli",
                "description": "Find potential SQL injection points"
            },
            "3": {
                "name": "AWS Keys",
                "command": "cat source_code.txt | gf aws-keys",
                "description": "Find AWS API keys"
            },
            "4": {
                "name": "S3 Buckets",
                "command": "cat response.txt | gf s3-buckets",
                "description": "Find S3 bucket references"
            },
            "5": {
                "name": "Debug Pages",
                "command": "cat urls.txt | gf debug-pages",
                "description": "Find debug/error pages"
            }
        },
        "Uro": {
            "1": {
                "name": "Remove Duplicates",
                "command": "cat urls.txt | uro",
                "description": "Remove duplicate URLs"
            },
            "2": {
                "name": "Clean Parameters",
                "command": "cat urls.txt | uro -p",
                "description": "Clean parameters"
            },
            "3": {
                "name": "With Output",
                "command": "cat urls.txt | uro > clean_urls.txt",
                "description": "Save cleaned URLs"
            },
            "4": {
                "name": "Preserve Regex",
                "command": "cat urls.txt | uro -r 'id=[0-9]+'",
                "description": "Preserve specific patterns"
            },
            "5": {
                "name": "Complete Cleaning",
                "command": "cat urls.txt | uro -a",
                "description": "Apply all cleaning methods"
            }
        },
        "Unfurl": {
            "1": {
                "name": "Extract Domains",
                "command": "cat urls.txt | unfurl domains",
                "description": "Extract unique domains"
            },
            "2": {
                "name": "Extract Paths",
                "command": "cat urls.txt | unfurl paths",
                "description": "Extract unique paths"
            },
            "3": {
                "name": "Extract Parameters",
                "command": "cat urls.txt | unfurl keys",
                "description": "Extract parameter names"
            },
            "4": {
                "name": "Format URLs",
                "command": "cat urls.txt | unfurl format %d%p",
                "description": "Format URLs as domain+path"
            },
            "5": {
                "name": "Filter Values",
                "command": "cat urls.txt | unfurl values",
                "description": "Extract parameter values"
            }
        },
        "Qsreplace": {
            "1": {
                "name": "Replace Parameter",
                "command": "cat urls.txt | qsreplace newvalue",
                "description": "Replace parameter values"
            },
            "2": {
                "name": "XSS Payload",
                "command": "cat urls.txt | qsreplace '\">\"><script>alert(1)</script>'",
                "description": "Insert XSS payload"
            },
            "3": {
                "name": "With Filtering",
                "command": "cat urls.txt | qsreplace payload | grep payload",
                "description": "Keep only successful replacements"
            },
            "4": {
                "name": "Filter Duplicates",
                "command": "cat urls.txt | qsreplace -a 'FUZZ'",
                "description": "Replace all parameters"
            },
            "5": {
                "name": "Change URL Part",
                "command": "cat urls.txt | qsreplace -u 'https://attacker.com'",
                "description": "Replace URL host"
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
            "\n[yellow]Select a command number or type 'back'[/yellow]",
            choices=list(commands.keys()) + ["back"],
            default="back"
        )

        if cmd_choice == "back":
            break

        command = commands[cmd_choice]["command"]
        execute_command(command)
