[31m--[ [0m[34mMatch #[0m[33m1[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000702[0m
       Tag: [34mSecurity.Backdoor.DataExfiltration.Environment[0m
  Severity: [36mImportant[0m, Confidence: [36mHigh[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/tox.ini[0m
   Pattern: [32m(env|environment).{1,50}(get|post|curl|nc|invoke-restmethod)[0m
[30;1m23 | [0m[35mcommands =[0m
[30;1m24 | [0m[35m    # Use -o only once, so we exercise both code paths.[0m
[30;1m25 | [0m[35m    coverage run -m hatch_fancy_pypi_readme tests/example_pyproject.toml -o {envtmpdir}{/}t.md[0m
[30;1m26 | [0m[35m    coverage run {envbindir}{/}hatch-fancy-pypi-readme tests/example_pyproject.toml[0m
[30;1m27 | [0m[35m[0m
[30;1m28 | [0m[35m[0m
[30;1m29 | [0m[35m[testenv:pre-commit][0m

[31m--[ [0m[34mMatch #[0m[33m2[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000700[0m
       Tag: [34mSecurity.Backdoor.DataExfiltration[0m
  Severity: [36mImportant[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/src/hatch_fancy_pypi_readme/hooks.py[0m
   Pattern: [32m\.(request|post|get)\([0m
[30;1m27 | [0m[35m            "text": build_text([0m
[30;1m28 | [0m[35m                config.fragments,[0m
[30;1m29 | [0m[35m                config.substitutions,[0m
[30;1m30 | [0m[35m                version=metadata.get("version", ""),[0m
[30;1m31 | [0m[35m            ),[0m
[30;1m32 | [0m[35m        }[0m
[30;1m33 | [0m[35m[0m

[31m--[ [0m[34mMatch #[0m[33m3[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000600[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Windows[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/src/hatch_fancy_pypi_readme/hooks.py[0m
   Pattern: [32m\s(advpack\.dll|appvlp|at|atbroker|bash|bginfo|bitsadmin|cdb|certutil|cl_invocation\.ps1|cl_mutexverifiers\.ps1|cmd|cmdkey|cmstp|comsvcs\.dll|control|csc|cscript|csi|devtoolslauncher|dfsvc|diskshadow|dnscmd|dnx|dotnet|dxcap|esentutl|eventvwr|excel|expand|extexport|extrac32|findstr|forfiles|ftp|gfxdownloadwrapper|gpscript|hh|ie4uinit|ieadvpack\.dll|ieaframe\.dll|ic|infdefaultinstall|installutil|jsc|makecab|manage-bde\.wsf|mavinject|mftrace|microsoft\.workflow\.compiler|mmc|msbuild|msconfig|msdeploy|msdt|mshta|mshtml\.dll|msc|msxsl|netsh|odbcconf|pcalua|pcwrun|pcwutl\.dll|pester\.bat|powerpnt|presentationhost|pubprn\.vbs|rcsi|reg|regasm|regedit|register-cimprovider|regsvcs|regsvr32|rpcping|rundll32|runonce|runscripthelper|sc|schtasks|scriptrunner|setupapi\.dll|shdocvw\.dll|shell32\.dll|slmgr\.vbs|sqldumper|sqlps|sqltoolsps|squirrel|syncappvpublishingserver|syncappvpublishingserver\.vbs|syssetup\.dll|te|tracker|tttracer|update|url\.dll|verclsid|vsjitdebugger|wab|winrm\.vbs|winword|wmic|wscript|wsl|wsreset|xwizard|zipfldr\.dll)\s[0m
[30;1m18 | [0m[35m[0m
[30;1m19 | [0m[35m    def update(self, metadata: dict[str, Any]) -> None:[0m
[30;1m20 | [0m[35m        """[0m
[30;1m21 | [0m[35m        Update the project table's metadata.[0m
[30;1m22 | [0m[35m        """[0m
[30;1m23 | [0m[35m        config = load_and_validate_config(self.config)[0m
[30;1m24 | [0m[35m[0m

[31m--[ [0m[34mMatch #[0m[33m4[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/tests/conftest.py[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m14 | [0m[35mdef _plugin_dir():[0m
[30;1m15 | [0m[35m    """[0m
[30;1m16 | [0m[35m    Install the plugin into a temporary directory with a random path to[0m
[30;1m17 | [0m[35m    prevent pip from caching it.[0m
[30;1m18 | [0m[35m[0m
[30;1m19 | [0m[35m    Copy only the src directory, pyproject.toml, and whatever is needed[0m
[30;1m20 | [0m[35m    to build ourselves.[0m

[31m--[ [0m[34mMatch #[0m[33m5[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/tests/test_fragments.py[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m112 | [0m[35m            == FileFragment.from_config([0m
[30;1m113 | [0m[35m                {[0m
[30;1m114 | [0m[35m                    "path": str(txt_path),[0m
[30;1m115 | [0m[35m                    "start-after": "<!-- cut after this -->\n\n",[0m
[30;1m116 | [0m[35m                    "end-before": "\n\n<!-- but before this -->",[0m
[30;1m117 | [0m[35m                }[0m
[30;1m118 | [0m[35m            ).render()[0m

[31m--[ [0m[34mMatch #[0m[33m6[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/tests/test_fragments.py[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m91 | [0m[35m        assert ([0m
[30;1m92 | [0m[35m            """# Boring Header[0m
[30;1m93 | [0m[35m[0m
[30;1m94 | [0m[35m<!-- cut after this -->[0m
[30;1m95 | [0m[35m[0m
[30;1m96 | [0m[35mThis is the *interesting* body!"""[0m
[30;1m97 | [0m[35m            == FileFragment.from_config([0m

[31m--[ [0m[34mMatch #[0m[33m7[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/tests/test_fragments.py[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m58 | [0m[35m            == FileFragment.from_config([0m
[30;1m59 | [0m[35m                {[0m
[30;1m60 | [0m[35m                    "path": str(txt_path),[0m
[30;1m61 | [0m[35m                    "start-after": "<!-- cut after this -->\n\n",[0m
[30;1m62 | [0m[35m                }[0m
[30;1m63 | [0m[35m            ).render()[0m
[30;1m64 | [0m[35m        )[0m

[31m--[ [0m[34mMatch #[0m[33m8[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000600[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Windows[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/tests/test_config.py[0m
   Pattern: [32m\s(advpack\.dll|appvlp|at|atbroker|bash|bginfo|bitsadmin|cdb|certutil|cl_invocation\.ps1|cl_mutexverifiers\.ps1|cmd|cmdkey|cmstp|comsvcs\.dll|control|csc|cscript|csi|devtoolslauncher|dfsvc|diskshadow|dnscmd|dnx|dotnet|dxcap|esentutl|eventvwr|excel|expand|extexport|extrac32|findstr|forfiles|ftp|gfxdownloadwrapper|gpscript|hh|ie4uinit|ieadvpack\.dll|ieaframe\.dll|ic|infdefaultinstall|installutil|jsc|makecab|manage-bde\.wsf|mavinject|mftrace|microsoft\.workflow\.compiler|mmc|msbuild|msconfig|msdeploy|msdt|mshta|mshtml\.dll|msc|msxsl|netsh|odbcconf|pcalua|pcwrun|pcwutl\.dll|pester\.bat|powerpnt|presentationhost|pubprn\.vbs|rcsi|reg|regasm|regedit|register-cimprovider|regsvcs|regsvr32|rpcping|rundll32|runonce|runscripthelper|sc|schtasks|scriptrunner|setupapi\.dll|shdocvw\.dll|shell32\.dll|slmgr\.vbs|sqldumper|sqlps|sqltoolsps|squirrel|syncappvpublishingserver|syncappvpublishingserver\.vbs|syssetup\.dll|te|tracker|tttracer|update|url\.dll|verclsid|vsjitdebugger|wab|winrm\.vbs|winword|wmic|wscript|wsl|wsreset|xwizard|zipfldr\.dll)\s[0m
[30;1m220 | [0m[35m            )[0m
[30;1m221 | [0m[35m[0m
[30;1m222 | [0m[35m        assert {[0m
[30;1m223 | [0m[35m            "'foo???' is not a valid regular expression: multiple repeat at "[0m
[30;1m224 | [0m[35m            "position 5"[0m
[30;1m225 | [0m[35m        } == set(ei.value.errors)[0m
[30;1m226 | [0m[35m[0m

[31m--[ [0m[34mMatch #[0m[33m9[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/README.md[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m187 | [0m[35m[0m
[30;1m188 | [0m[35m> [!TIP][0m
[30;1m189 | [0m[35m>[0m
[30;1m190 | [0m[35m> - You can insert the same file **multiple times** – each time a different part![0m
[30;1m191 | [0m[35m> - The order of the options in a fragment block does *not* matter.[0m
[30;1m192 | [0m[35m>   They’re always executed in the same order:[0m
[30;1m193 | [0m[35m>[0m

[31m--[ [0m[34mMatch #[0m[33m10[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/README.md[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m172 | [0m[35m```toml[0m
[30;1m173 | [0m[35m[[tool.hatch.metadata.hooks.fancy-pypi-readme.fragments]][0m
[30;1m174 | [0m[35mpath = "path.md"[0m
[30;1m175 | [0m[35mstart-after = "<!-- cut after this -->\n\n"[0m
[30;1m176 | [0m[35mend-before = "\n\n<!-- but before this -->"[0m
[30;1m177 | [0m[35mpattern = "the (.*?) body"[0m
[30;1m178 | [0m[35m```[0m

[31m--[ [0m[34mMatch #[0m[33m11[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/README.md[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m158 | [0m[35m```markdown[0m
[30;1m159 | [0m[35m# Boring Header[0m
[30;1m160 | [0m[35m[0m
[30;1m161 | [0m[35m<!-- cut after this -->[0m
[30;1m162 | [0m[35m[0m
[30;1m163 | [0m[35mThis is the *interesting* body![0m
[30;1m164 | [0m[35m[0m

[31m--[ [0m[34mMatch #[0m[33m12[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/README.md[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m151 | [0m[35m  re.search(pattern, whatever_is_left_after_slicing, re.DOTALL).group(1)[0m
[30;1m152 | [0m[35m  ```[0m
[30;1m153 | [0m[35m[0m
[30;1m154 | [0m[35m  to find it.[0m
[30;1m155 | [0m[35m[0m
[30;1m156 | [0m[35mBoth Markdown and reStructuredText (reST) have comments (`<!-- this is a Markdown comment -->` and `[0m
[30;1m157 | [0m[35m[0m

[31m--[ [0m[34mMatch #[0m[33m13[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/README.md[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m136 | [0m[35mpath = "AUTHORS.md"[0m
[30;1m137 | [0m[35m```[0m
[30;1m138 | [0m[35m[0m
[30;1m139 | [0m[35mAdditionally it’s possible to cut away parts of the file before appending it:[0m
[30;1m140 | [0m[35m[0m
[30;1m141 | [0m[35m- **`start-after`** cuts away everything *before and including* the string specified.[0m
[30;1m142 | [0m[35m- **`start-at`** cuts away everything before the string specified too, but the string itself is *pre[0m

[31m--[ [0m[34mMatch #[0m[33m14[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000600[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Windows[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/README.md[0m
   Pattern: [32m\s(advpack\.dll|appvlp|at|atbroker|bash|bginfo|bitsadmin|cdb|certutil|cl_invocation\.ps1|cl_mutexverifiers\.ps1|cmd|cmdkey|cmstp|comsvcs\.dll|control|csc|cscript|csi|devtoolslauncher|dfsvc|diskshadow|dnscmd|dnx|dotnet|dxcap|esentutl|eventvwr|excel|expand|extexport|extrac32|findstr|forfiles|ftp|gfxdownloadwrapper|gpscript|hh|ie4uinit|ieadvpack\.dll|ieaframe\.dll|ic|infdefaultinstall|installutil|jsc|makecab|manage-bde\.wsf|mavinject|mftrace|microsoft\.workflow\.compiler|mmc|msbuild|msconfig|msdeploy|msdt|mshta|mshtml\.dll|msc|msxsl|netsh|odbcconf|pcalua|pcwrun|pcwutl\.dll|pester\.bat|powerpnt|presentationhost|pubprn\.vbs|rcsi|reg|regasm|regedit|register-cimprovider|regsvcs|regsvr32|rpcping|rundll32|runonce|runscripthelper|sc|schtasks|scriptrunner|setupapi\.dll|shdocvw\.dll|shell32\.dll|slmgr\.vbs|sqldumper|sqlps|sqltoolsps|squirrel|syncappvpublishingserver|syncappvpublishingserver\.vbs|syssetup\.dll|te|tracker|tttracer|update|url\.dll|verclsid|vsjitdebugger|wab|winrm\.vbs|winword|wmic|wscript|wsl|wsreset|xwizard|zipfldr\.dll)\s[0m
[30;1m140 | [0m[35m[0m
[30;1m141 | [0m[35m- **`start-after`** cuts away everything *before and including* the string specified.[0m
[30;1m142 | [0m[35m- **`start-at`** cuts away everything before the string specified too, but the string itself is *pre[0m
[30;1m143 | [0m[35m  This is useful when you want to start at a heading without adding a marker *before* it.[0m
[30;1m144 | [0m[35m[0m
[30;1m145 | [0m[35m  `start-after` and `start-at` are mutually exclusive.[0m
[30;1m146 | [0m[35m- **`end-before`** cuts away everything after.[0m

[31m--[ [0m[34mMatch #[0m[33m15[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/CHANGELOG.md[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m49 | [0m[35m[0m
[30;1m50 | [0m[35m### Changed[0m
[30;1m51 | [0m[35m[0m
[30;1m52 | [0m[35m- Removed another circular dependency: this time the wonderful [*jsonschema*](https://python-jsonsch[0m
[30;1m53 | [0m[35m  The price of building packaging tools is to not use packages.[0m
[30;1m54 | [0m[35m[0m
[30;1m55 | [0m[35m[0m

[31m--[ [0m[34mMatch #[0m[33m16[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000600[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Windows[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/CHANGELOG.md[0m
   Pattern: [32m\s(advpack\.dll|appvlp|at|atbroker|bash|bginfo|bitsadmin|cdb|certutil|cl_invocation\.ps1|cl_mutexverifiers\.ps1|cmd|cmdkey|cmstp|comsvcs\.dll|control|csc|cscript|csi|devtoolslauncher|dfsvc|diskshadow|dnscmd|dnx|dotnet|dxcap|esentutl|eventvwr|excel|expand|extexport|extrac32|findstr|forfiles|ftp|gfxdownloadwrapper|gpscript|hh|ie4uinit|ieadvpack\.dll|ieaframe\.dll|ic|infdefaultinstall|installutil|jsc|makecab|manage-bde\.wsf|mavinject|mftrace|microsoft\.workflow\.compiler|mmc|msbuild|msconfig|msdeploy|msdt|mshta|mshtml\.dll|msc|msxsl|netsh|odbcconf|pcalua|pcwrun|pcwutl\.dll|pester\.bat|powerpnt|presentationhost|pubprn\.vbs|rcsi|reg|regasm|regedit|register-cimprovider|regsvcs|regsvr32|rpcping|rundll32|runonce|runscripthelper|sc|schtasks|scriptrunner|setupapi\.dll|shdocvw\.dll|shell32\.dll|slmgr\.vbs|sqldumper|sqlps|sqltoolsps|squirrel|syncappvpublishingserver|syncappvpublishingserver\.vbs|syssetup\.dll|te|tracker|tttracer|update|url\.dll|verclsid|vsjitdebugger|wab|winrm\.vbs|winword|wmic|wscript|wsl|wsreset|xwizard|zipfldr\.dll)\s[0m
[30;1m5 | [0m[35mThe format is based on [*Keep a Changelog*](https://keepachangelog.com/en/1.0.0/) and this project a[0m
[30;1m6 | [0m[35m[0m
[30;1m7 | [0m[35mThe **first number** of the version is the year.[0m
[30;1m8 | [0m[35mThe **second number** is incremented with each release, starting at 1 for each year.[0m
[30;1m9 | [0m[35mThe **third number** is for emergencies when we need to start branches for older releases.[0m
[30;1m10 | [0m[35m[0m
[30;1m11 | [0m[35m<!-- changelog follows -->[0m

[31m--[ [0m[34mMatch #[0m[33m17[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000700[0m
       Tag: [34mSecurity.Backdoor.DataExfiltration[0m
  Severity: [36mImportant[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/src/hatch_fancy_pypi_readme/_substitutions.py[0m
   Pattern: [32m\.(request|post|get)\([0m
[30;1m40 | [0m[35m                f"{cfg['pattern']!r} is not a valid regular expression: {e}"[0m
[30;1m41 | [0m[35m            )[0m
[30;1m42 | [0m[35m[0m
[30;1m43 | [0m[35m        replacement = cfg.get("replacement")[0m
[30;1m44 | [0m[35m        if replacement is None:[0m
[30;1m45 | [0m[35m            errs.append(f"Substitution {cfg} is missing a 'replacement' key.")[0m
[30;1m46 | [0m[35m        elif not isinstance(replacement, str):[0m

[31m--[ [0m[34mMatch #[0m[33m18[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000700[0m
       Tag: [34mSecurity.Backdoor.DataExfiltration[0m
  Severity: [36mImportant[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/src/hatch_fancy_pypi_readme/_substitutions.py[0m
   Pattern: [32m\.(request|post|get)\([0m
[30;1m22 | [0m[35m        errs = [][0m
[30;1m23 | [0m[35m        flags = 0[0m
[30;1m24 | [0m[35m[0m
[30;1m25 | [0m[35m        ignore_case = cfg.get("ignore-case", False)[0m
[30;1m26 | [0m[35m        if not isinstance(ignore_case, bool):[0m
[30;1m27 | [0m[35m            errs.append([0m
[30;1m28 | [0m[35m                f"Value {ignore_case!r} for 'ignore-case' is not a bool."[0m

[31m--[ [0m[34mMatch #[0m[33m19[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000600[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Windows[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/pyproject.toml[0m
   Pattern: [32m\s(advpack\.dll|appvlp|at|atbroker|bash|bginfo|bitsadmin|cdb|certutil|cl_invocation\.ps1|cl_mutexverifiers\.ps1|cmd|cmdkey|cmstp|comsvcs\.dll|control|csc|cscript|csi|devtoolslauncher|dfsvc|diskshadow|dnscmd|dnx|dotnet|dxcap|esentutl|eventvwr|excel|expand|extexport|extrac32|findstr|forfiles|ftp|gfxdownloadwrapper|gpscript|hh|ie4uinit|ieadvpack\.dll|ieaframe\.dll|ic|infdefaultinstall|installutil|jsc|makecab|manage-bde\.wsf|mavinject|mftrace|microsoft\.workflow\.compiler|mmc|msbuild|msconfig|msdeploy|msdt|mshta|mshtml\.dll|msc|msxsl|netsh|odbcconf|pcalua|pcwrun|pcwutl\.dll|pester\.bat|powerpnt|presentationhost|pubprn\.vbs|rcsi|reg|regasm|regedit|register-cimprovider|regsvcs|regsvr32|rpcping|rundll32|runonce|runscripthelper|sc|schtasks|scriptrunner|setupapi\.dll|shdocvw\.dll|shell32\.dll|slmgr\.vbs|sqldumper|sqlps|sqltoolsps|squirrel|syncappvpublishingserver|syncappvpublishingserver\.vbs|syssetup\.dll|te|tracker|tttracer|update|url\.dll|verclsid|vsjitdebugger|wab|winrm\.vbs|winword|wmic|wscript|wsl|wsreset|xwizard|zipfldr\.dll)\s[0m
[30;1m126 | [0m[35mselect = ["ALL"][0m
[30;1m127 | [0m[35m[0m
[30;1m128 | [0m[35mignore = [[0m
[30;1m129 | [0m[35m  "ANN",      # Mypy is better at this.[0m
[30;1m130 | [0m[35m  "C901",     # Leave complexity to me.[0m
[30;1m131 | [0m[35m  "COM",      # Leave commas to Black.[0m
[30;1m132 | [0m[35m  "D",        # We have different ideas about docstrings.[0m

[31m--[ [0m[34mMatch #[0m[33m20[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000600[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Windows[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/pyproject.toml[0m
   Pattern: [32m\s(advpack\.dll|appvlp|at|atbroker|bash|bginfo|bitsadmin|cdb|certutil|cl_invocation\.ps1|cl_mutexverifiers\.ps1|cmd|cmdkey|cmstp|comsvcs\.dll|control|csc|cscript|csi|devtoolslauncher|dfsvc|diskshadow|dnscmd|dnx|dotnet|dxcap|esentutl|eventvwr|excel|expand|extexport|extrac32|findstr|forfiles|ftp|gfxdownloadwrapper|gpscript|hh|ie4uinit|ieadvpack\.dll|ieaframe\.dll|ic|infdefaultinstall|installutil|jsc|makecab|manage-bde\.wsf|mavinject|mftrace|microsoft\.workflow\.compiler|mmc|msbuild|msconfig|msdeploy|msdt|mshta|mshtml\.dll|msc|msxsl|netsh|odbcconf|pcalua|pcwrun|pcwutl\.dll|pester\.bat|powerpnt|presentationhost|pubprn\.vbs|rcsi|reg|regasm|regedit|register-cimprovider|regsvcs|regsvr32|rpcping|rundll32|runonce|runscripthelper|sc|schtasks|scriptrunner|setupapi\.dll|shdocvw\.dll|shell32\.dll|slmgr\.vbs|sqldumper|sqlps|sqltoolsps|squirrel|syncappvpublishingserver|syncappvpublishingserver\.vbs|syssetup\.dll|te|tracker|tttracer|update|url\.dll|verclsid|vsjitdebugger|wab|winrm\.vbs|winword|wmic|wscript|wsl|wsreset|xwizard|zipfldr\.dll)\s[0m
[30;1m53 | [0m[35m[0m
[30;1m54 | [0m[35m*hatch-fancy-pypi-readme* is an MIT-licensed metadata plugin for [Hatch](https://hatch.pypa.io/) by [0m
[30;1m55 | [0m[35m[0m
[30;1m56 | [0m[35mIts purpose is to help you to have fancy PyPI readmes – unlike *this* one you’re looking at right no[0m
[30;1m57 | [0m[35m[0m
[30;1m58 | [0m[35mPlease check out the [documentation](https://github.com/hynek/hatch-fancy-pypi-readme#readme) to see[0m
[30;1m59 | [0m[35m"""[0m

[31m--[ [0m[34mMatch #[0m[33m21[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/tests/test_substitutions.py[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m70 | [0m[35m        Pydantic examples work.[0m
[30;1m71 | [0m[35m        https://github.com/hynek/hatch-fancy-pypi-readme/issues/9#issuecomment-1238584908[0m
[30;1m72 | [0m[35m        """[0m
[30;1m73 | [0m[35m        assert expect == Substituter.from_config([0m
[30;1m74 | [0m[35m            {[0m
[30;1m75 | [0m[35m                "pattern": pat,[0m
[30;1m76 | [0m[35m                "replacement": repl,[0m

[31m--[ [0m[34mMatch #[0m[33m22[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/workflows/ci.yml[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m143 | [0m[35m          cache: pip[0m
[30;1m144 | [0m[35m          python-version-file: .python-version-default[0m
[30;1m145 | [0m[35m[0m
[30;1m146 | [0m[35m      - run: python -Im pip install -e .[dev][0m
[30;1m147 | [0m[35m      - run: python -Ic 'import hatch_fancy_pypi_readme'[0m
[30;1m148 | [0m[35m      - run: python -m hatch_fancy_pypi_readme tests/example_pyproject.toml[0m
[30;1m149 | [0m[35m      - run: hatch-fancy-pypi-readme tests/example_pyproject.toml[0m

[31m--[ [0m[34mMatch #[0m[33m23[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/workflows/ci.yml[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m140 | [0m[35m      - uses: actions/checkout@v4[0m
[30;1m141 | [0m[35m      - uses: actions/setup-python@v4[0m
[30;1m142 | [0m[35m        with:[0m
[30;1m143 | [0m[35m          cache: pip[0m
[30;1m144 | [0m[35m          python-version-file: .python-version-default[0m
[30;1m145 | [0m[35m[0m
[30;1m146 | [0m[35m      - run: python -Im pip install -e .[dev][0m
[30;1m147 | [0m[35m      - run: python -Ic 'import hatch_fancy_pypi_readme'[0m

[31m--[ [0m[34mMatch #[0m[33m24[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/workflows/ci.yml[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m130 | [0m[35m      - run: python -Im tox run -e mypy[0m
[30;1m131 | [0m[35m[0m
[30;1m132 | [0m[35m  install-dev:[0m
[30;1m133 | [0m[35m    name: Verify dev env[0m
[30;1m134 | [0m[35m    runs-on: ${{ matrix.os }}[0m
[30;1m135 | [0m[35m    strategy:[0m
[30;1m136 | [0m[35m      matrix:[0m
[30;1m137 | [0m[35m        os: [ubuntu-latest, windows-latest][0m

[31m--[ [0m[34mMatch #[0m[33m25[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/workflows/ci.yml[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m125 | [0m[35m          cache: pip[0m
[30;1m126 | [0m[35m          python-version-file: .python-version-default[0m
[30;1m127 | [0m[35m[0m
[30;1m128 | [0m[35m      - run: python -Im pip install tox[0m
[30;1m129 | [0m[35m[0m
[30;1m130 | [0m[35m      - run: python -Im tox run -e mypy[0m
[30;1m131 | [0m[35m[0m

[31m--[ [0m[34mMatch #[0m[33m26[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/workflows/ci.yml[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m122 | [0m[35m      - run: tar xf dist/*.tar.gz --strip-components=1  # needed for config files[0m
[30;1m123 | [0m[35m      - uses: actions/setup-python@v4[0m
[30;1m124 | [0m[35m        with:[0m
[30;1m125 | [0m[35m          cache: pip[0m
[30;1m126 | [0m[35m          python-version-file: .python-version-default[0m
[30;1m127 | [0m[35m[0m
[30;1m128 | [0m[35m      - run: python -Im pip install tox[0m
[30;1m129 | [0m[35m[0m

[31m--[ [0m[34mMatch #[0m[33m27[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/workflows/ci.yml[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m119 | [0m[35m        with:[0m
[30;1m120 | [0m[35m          name: Packages[0m
[30;1m121 | [0m[35m          path: dist[0m
[30;1m122 | [0m[35m      - run: tar xf dist/*.tar.gz --strip-components=1  # needed for config files[0m
[30;1m123 | [0m[35m      - uses: actions/setup-python@v4[0m
[30;1m124 | [0m[35m        with:[0m
[30;1m125 | [0m[35m          cache: pip[0m

[31m--[ [0m[34mMatch #[0m[33m28[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/workflows/ci.yml[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m89 | [0m[35m[0m
[30;1m90 | [0m[35m      - name: Combine coverage and fail if it's <100%.[0m
[30;1m91 | [0m[35m        run: |[0m
[30;1m92 | [0m[35m          python -Im pip install --upgrade coverage[toml][0m
[30;1m93 | [0m[35m[0m
[30;1m94 | [0m[35m          python -Im coverage combine[0m
[30;1m95 | [0m[35m          python -Im coverage html --skip-covered --skip-empty[0m

[31m--[ [0m[34mMatch #[0m[33m29[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/workflows/ci.yml[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m79 | [0m[35m      - uses: actions/checkout@v4[0m
[30;1m80 | [0m[35m      - uses: actions/setup-python@v4[0m
[30;1m81 | [0m[35m        with:[0m
[30;1m82 | [0m[35m          cache: pip[0m
[30;1m83 | [0m[35m          python-version-file: .python-version-default[0m
[30;1m84 | [0m[35m[0m
[30;1m85 | [0m[35m      - name: Download coverage data[0m
[30;1m86 | [0m[35m        uses: actions/download-artifact@v3[0m

[31m--[ [0m[34mMatch #[0m[33m30[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/workflows/ci.yml[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m56 | [0m[35m          python-version: ${{ matrix.python-version }}[0m
[30;1m57 | [0m[35m          allow-prereleases: true[0m
[30;1m58 | [0m[35m[0m
[30;1m59 | [0m[35m      - run: python -Im pip install tox[0m
[30;1m60 | [0m[35m[0m
[30;1m61 | [0m[35m      - run: |[0m
[30;1m62 | [0m[35m          python -Im tox run \[0m

[31m--[ [0m[34mMatch #[0m[33m31[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/workflows/ci.yml[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m52 | [0m[35m      - run: tar xf dist/*.tar.gz --strip-components=1  # needed for config files[0m
[30;1m53 | [0m[35m      - uses: actions/setup-python@v4[0m
[30;1m54 | [0m[35m        with:[0m
[30;1m55 | [0m[35m          cache: pip[0m
[30;1m56 | [0m[35m          python-version: ${{ matrix.python-version }}[0m
[30;1m57 | [0m[35m          allow-prereleases: true[0m
[30;1m58 | [0m[35m[0m
[30;1m59 | [0m[35m      - run: python -Im pip install tox[0m

[31m--[ [0m[34mMatch #[0m[33m32[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/workflows/ci.yml[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m49 | [0m[35m        with:[0m
[30;1m50 | [0m[35m          name: Packages[0m
[30;1m51 | [0m[35m          path: dist[0m
[30;1m52 | [0m[35m      - run: tar xf dist/*.tar.gz --strip-components=1  # needed for config files[0m
[30;1m53 | [0m[35m      - uses: actions/setup-python@v4[0m
[30;1m54 | [0m[35m        with:[0m
[30;1m55 | [0m[35m          cache: pip[0m

[31m--[ [0m[34mMatch #[0m[33m33[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/CODE_OF_CONDUCT.md[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m110 | [0m[35mstandards, including sustained inappropriate behavior, harassment of an[0m
[30;1m111 | [0m[35mindividual, or aggression toward or disparagement of classes of individuals.[0m
[30;1m112 | [0m[35m[0m
[30;1m113 | [0m[35m**Consequence**: A permanent ban from any sort of public interaction within the[0m
[30;1m114 | [0m[35mcommunity.[0m
[30;1m115 | [0m[35m[0m
[30;1m116 | [0m[35m## Attribution[0m

[31m--[ [0m[34mMatch #[0m[33m34[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/CODE_OF_CONDUCT.md[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m98 | [0m[35m**Community Impact**: A serious violation of community standards, including[0m
[30;1m99 | [0m[35msustained inappropriate behavior.[0m
[30;1m100 | [0m[35m[0m
[30;1m101 | [0m[35m**Consequence**: A temporary ban from any sort of interaction or public[0m
[30;1m102 | [0m[35mcommunication with the community for a specified period of time. No public or[0m
[30;1m103 | [0m[35mprivate interaction with the people involved, including unsolicited interaction[0m
[30;1m104 | [0m[35mwith those enforcing the Code of Conduct, is allowed during this period.[0m

[31m--[ [0m[34mMatch #[0m[33m35[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000600[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Windows[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/CODE_OF_CONDUCT.md[0m
   Pattern: [32m\s(advpack\.dll|appvlp|at|atbroker|bash|bginfo|bitsadmin|cdb|certutil|cl_invocation\.ps1|cl_mutexverifiers\.ps1|cmd|cmdkey|cmstp|comsvcs\.dll|control|csc|cscript|csi|devtoolslauncher|dfsvc|diskshadow|dnscmd|dnx|dotnet|dxcap|esentutl|eventvwr|excel|expand|extexport|extrac32|findstr|forfiles|ftp|gfxdownloadwrapper|gpscript|hh|ie4uinit|ieadvpack\.dll|ieaframe\.dll|ic|infdefaultinstall|installutil|jsc|makecab|manage-bde\.wsf|mavinject|mftrace|microsoft\.workflow\.compiler|mmc|msbuild|msconfig|msdeploy|msdt|mshta|mshtml\.dll|msc|msxsl|netsh|odbcconf|pcalua|pcwrun|pcwutl\.dll|pester\.bat|powerpnt|presentationhost|pubprn\.vbs|rcsi|reg|regasm|regedit|register-cimprovider|regsvcs|regsvr32|rpcping|rundll32|runonce|runscripthelper|sc|schtasks|scriptrunner|setupapi\.dll|shdocvw\.dll|shell32\.dll|slmgr\.vbs|sqldumper|sqlps|sqltoolsps|squirrel|syncappvpublishingserver|syncappvpublishingserver\.vbs|syssetup\.dll|te|tracker|tttracer|update|url\.dll|verclsid|vsjitdebugger|wab|winrm\.vbs|winword|wmic|wscript|wsl|wsreset|xwizard|zipfldr\.dll)\s[0m
[30;1m123 | [0m[35m[Mozilla's code of conduct enforcement ladder][Mozilla CoC].[0m
[30;1m124 | [0m[35m[0m
[30;1m125 | [0m[35mFor answers to common questions about this code of conduct, see the FAQ at[0m
[30;1m126 | [0m[35m[https://www.contributor-covenant.org/faq][FAQ]. Translations are available at[0m
[30;1m127 | [0m[35m[https://www.contributor-covenant.org/translations][translations].[0m
[30;1m128 | [0m[35m[0m
[30;1m129 | [0m[35m[homepage]: https://www.contributor-covenant.org[0m
[30;1m130 | [0m[35m[v2.1]: https://www.contributor-covenant.org/version/2/1/code_of_conduct.html[0m

[31m--[ [0m[34mMatch #[0m[33m36[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000600[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Windows[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/CODE_OF_CONDUCT.md[0m
   Pattern: [32m\s(advpack\.dll|appvlp|at|atbroker|bash|bginfo|bitsadmin|cdb|certutil|cl_invocation\.ps1|cl_mutexverifiers\.ps1|cmd|cmdkey|cmstp|comsvcs\.dll|control|csc|cscript|csi|devtoolslauncher|dfsvc|diskshadow|dnscmd|dnx|dotnet|dxcap|esentutl|eventvwr|excel|expand|extexport|extrac32|findstr|forfiles|ftp|gfxdownloadwrapper|gpscript|hh|ie4uinit|ieadvpack\.dll|ieaframe\.dll|ic|infdefaultinstall|installutil|jsc|makecab|manage-bde\.wsf|mavinject|mftrace|microsoft\.workflow\.compiler|mmc|msbuild|msconfig|msdeploy|msdt|mshta|mshtml\.dll|msc|msxsl|netsh|odbcconf|pcalua|pcwrun|pcwutl\.dll|pester\.bat|powerpnt|presentationhost|pubprn\.vbs|rcsi|reg|regasm|regedit|register-cimprovider|regsvcs|regsvr32|rpcping|rundll32|runonce|runscripthelper|sc|schtasks|scriptrunner|setupapi\.dll|shdocvw\.dll|shell32\.dll|slmgr\.vbs|sqldumper|sqlps|sqltoolsps|squirrel|syncappvpublishingserver|syncappvpublishingserver\.vbs|syssetup\.dll|te|tracker|tttracer|update|url\.dll|verclsid|vsjitdebugger|wab|winrm\.vbs|winword|wmic|wscript|wsl|wsreset|xwizard|zipfldr\.dll)\s[0m
[30;1m122 | [0m[35mCommunity Impact Guidelines were inspired by[0m
[30;1m123 | [0m[35m[Mozilla's code of conduct enforcement ladder][Mozilla CoC].[0m
[30;1m124 | [0m[35m[0m
[30;1m125 | [0m[35mFor answers to common questions about this code of conduct, see the FAQ at[0m
[30;1m126 | [0m[35m[https://www.contributor-covenant.org/faq][FAQ]. Translations are available at[0m
[30;1m127 | [0m[35m[https://www.contributor-covenant.org/translations][translations].[0m
[30;1m128 | [0m[35m[0m
[30;1m129 | [0m[35m[homepage]: https://www.contributor-covenant.org[0m

[31m--[ [0m[34mMatch #[0m[33m37[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000600[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Windows[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/CODE_OF_CONDUCT.md[0m
   Pattern: [32m\s(advpack\.dll|appvlp|at|atbroker|bash|bginfo|bitsadmin|cdb|certutil|cl_invocation\.ps1|cl_mutexverifiers\.ps1|cmd|cmdkey|cmstp|comsvcs\.dll|control|csc|cscript|csi|devtoolslauncher|dfsvc|diskshadow|dnscmd|dnx|dotnet|dxcap|esentutl|eventvwr|excel|expand|extexport|extrac32|findstr|forfiles|ftp|gfxdownloadwrapper|gpscript|hh|ie4uinit|ieadvpack\.dll|ieaframe\.dll|ic|infdefaultinstall|installutil|jsc|makecab|manage-bde\.wsf|mavinject|mftrace|microsoft\.workflow\.compiler|mmc|msbuild|msconfig|msdeploy|msdt|mshta|mshtml\.dll|msc|msxsl|netsh|odbcconf|pcalua|pcwrun|pcwutl\.dll|pester\.bat|powerpnt|presentationhost|pubprn\.vbs|rcsi|reg|regasm|regedit|register-cimprovider|regsvcs|regsvr32|rpcping|rundll32|runonce|runscripthelper|sc|schtasks|scriptrunner|setupapi\.dll|shdocvw\.dll|shell32\.dll|slmgr\.vbs|sqldumper|sqlps|sqltoolsps|squirrel|syncappvpublishingserver|syncappvpublishingserver\.vbs|syssetup\.dll|te|tracker|tttracer|update|url\.dll|verclsid|vsjitdebugger|wab|winrm\.vbs|winword|wmic|wscript|wsl|wsreset|xwizard|zipfldr\.dll)\s[0m
[30;1m116 | [0m[35m## Attribution[0m
[30;1m117 | [0m[35m[0m
[30;1m118 | [0m[35mThis Code of Conduct is adapted from the [Contributor Covenant][homepage],[0m
[30;1m119 | [0m[35mversion 2.1, available at[0m
[30;1m120 | [0m[35m[https://www.contributor-covenant.org/version/2/1/code_of_conduct.html][v2.1].[0m
[30;1m121 | [0m[35m[0m
[30;1m122 | [0m[35mCommunity Impact Guidelines were inspired by[0m
[30;1m123 | [0m[35m[Mozilla's code of conduct enforcement ladder][Mozilla CoC].[0m

[31m--[ [0m[34mMatch #[0m[33m38[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000600[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Windows[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/CODE_OF_CONDUCT.md[0m
   Pattern: [32m\s(advpack\.dll|appvlp|at|atbroker|bash|bginfo|bitsadmin|cdb|certutil|cl_invocation\.ps1|cl_mutexverifiers\.ps1|cmd|cmdkey|cmstp|comsvcs\.dll|control|csc|cscript|csi|devtoolslauncher|dfsvc|diskshadow|dnscmd|dnx|dotnet|dxcap|esentutl|eventvwr|excel|expand|extexport|extrac32|findstr|forfiles|ftp|gfxdownloadwrapper|gpscript|hh|ie4uinit|ieadvpack\.dll|ieaframe\.dll|ic|infdefaultinstall|installutil|jsc|makecab|manage-bde\.wsf|mavinject|mftrace|microsoft\.workflow\.compiler|mmc|msbuild|msconfig|msdeploy|msdt|mshta|mshtml\.dll|msc|msxsl|netsh|odbcconf|pcalua|pcwrun|pcwutl\.dll|pester\.bat|powerpnt|presentationhost|pubprn\.vbs|rcsi|reg|regasm|regedit|register-cimprovider|regsvcs|regsvr32|rpcping|rundll32|runonce|runscripthelper|sc|schtasks|scriptrunner|setupapi\.dll|shdocvw\.dll|shell32\.dll|slmgr\.vbs|sqldumper|sqlps|sqltoolsps|squirrel|syncappvpublishingserver|syncappvpublishingserver\.vbs|syssetup\.dll|te|tracker|tttracer|update|url\.dll|verclsid|vsjitdebugger|wab|winrm\.vbs|winword|wmic|wscript|wsl|wsreset|xwizard|zipfldr\.dll)\s[0m
[30;1m60 | [0m[35m## Enforcement[0m
[30;1m61 | [0m[35m[0m
[30;1m62 | [0m[35mInstances of abusive, harassing, or otherwise unacceptable behavior may be[0m
[30;1m63 | [0m[35mreported to the community leaders responsible for enforcement at[0m
[30;1m64 | [0m[35m<mailto:hs@ox.cx>.[0m
[30;1m65 | [0m[35mAll complaints will be reviewed and investigated promptly and fairly.[0m
[30;1m66 | [0m[35m[0m
[30;1m67 | [0m[35mAll community leaders are obligated to respect the privacy and security of the[0m

[31m--[ [0m[34mMatch #[0m[33m39[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000600[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Windows[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/CODE_OF_CONDUCT.md[0m
   Pattern: [32m\s(advpack\.dll|appvlp|at|atbroker|bash|bginfo|bitsadmin|cdb|certutil|cl_invocation\.ps1|cl_mutexverifiers\.ps1|cmd|cmdkey|cmstp|comsvcs\.dll|control|csc|cscript|csi|devtoolslauncher|dfsvc|diskshadow|dnscmd|dnx|dotnet|dxcap|esentutl|eventvwr|excel|expand|extexport|extrac32|findstr|forfiles|ftp|gfxdownloadwrapper|gpscript|hh|ie4uinit|ieadvpack\.dll|ieaframe\.dll|ic|infdefaultinstall|installutil|jsc|makecab|manage-bde\.wsf|mavinject|mftrace|microsoft\.workflow\.compiler|mmc|msbuild|msconfig|msdeploy|msdt|mshta|mshtml\.dll|msc|msxsl|netsh|odbcconf|pcalua|pcwrun|pcwutl\.dll|pester\.bat|powerpnt|presentationhost|pubprn\.vbs|rcsi|reg|regasm|regedit|register-cimprovider|regsvcs|regsvr32|rpcping|rundll32|runonce|runscripthelper|sc|schtasks|scriptrunner|setupapi\.dll|shdocvw\.dll|shell32\.dll|slmgr\.vbs|sqldumper|sqlps|sqltoolsps|squirrel|syncappvpublishingserver|syncappvpublishingserver\.vbs|syssetup\.dll|te|tracker|tttracer|update|url\.dll|verclsid|vsjitdebugger|wab|winrm\.vbs|winword|wmic|wscript|wsl|wsreset|xwizard|zipfldr\.dll)\s[0m
[30;1m55 | [0m[35man individual is officially representing the community in public spaces.[0m
[30;1m56 | [0m[35mExamples of representing our community include using an official e-mail address,[0m
[30;1m57 | [0m[35mposting via an official social media account, or acting as an appointed[0m
[30;1m58 | [0m[35mrepresentative at an online or offline event.[0m
[30;1m59 | [0m[35m[0m
[30;1m60 | [0m[35m## Enforcement[0m
[30;1m61 | [0m[35m[0m

[31m--[ [0m[34mMatch #[0m[33m40[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/tests/example_changelog.md[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m4 | [0m[35mYour don't want this as part of your PyPI readme![0m
[30;1m5 | [0m[35m[0m
[30;1m6 | [0m[35mNote that there's issue/PR IDs behind the changelog entries.[0m
[30;1m7 | [0m[35mWouldn't it be nice if they were links in your PyPI readme?[0m
[30;1m8 | [0m[35m[0m
[30;1m9 | [0m[35m<!-- changelog follows -->[0m
[30;1m10 | [0m[35m[0m

[31m--[ [0m[34mMatch #[0m[33m41[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/tests/example_text.md[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m1 | [0m[35m# Boring Header[0m
[30;1m2 | [0m[35m[0m
[30;1m3 | [0m[35m<!-- cut after this -->[0m
[30;1m4 | [0m[35m[0m
[30;1m5 | [0m[35mThis is the *interesting* body![0m
[30;1m6 | [0m[35m[0m

[31m--[ [0m[34mMatch #[0m[33m42[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000600[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Windows[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/CONTRIBUTING.md[0m
   Pattern: [32m\s(advpack\.dll|appvlp|at|atbroker|bash|bginfo|bitsadmin|cdb|certutil|cl_invocation\.ps1|cl_mutexverifiers\.ps1|cmd|cmdkey|cmstp|comsvcs\.dll|control|csc|cscript|csi|devtoolslauncher|dfsvc|diskshadow|dnscmd|dnx|dotnet|dxcap|esentutl|eventvwr|excel|expand|extexport|extrac32|findstr|forfiles|ftp|gfxdownloadwrapper|gpscript|hh|ie4uinit|ieadvpack\.dll|ieaframe\.dll|ic|infdefaultinstall|installutil|jsc|makecab|manage-bde\.wsf|mavinject|mftrace|microsoft\.workflow\.compiler|mmc|msbuild|msconfig|msdeploy|msdt|mshta|mshtml\.dll|msc|msxsl|netsh|odbcconf|pcalua|pcwrun|pcwutl\.dll|pester\.bat|powerpnt|presentationhost|pubprn\.vbs|rcsi|reg|regasm|regedit|register-cimprovider|regsvcs|regsvr32|rpcping|rundll32|runonce|runscripthelper|sc|schtasks|scriptrunner|setupapi\.dll|shdocvw\.dll|shell32\.dll|slmgr\.vbs|sqldumper|sqlps|sqltoolsps|squirrel|syncappvpublishingserver|syncappvpublishingserver\.vbs|syssetup\.dll|te|tracker|tttracer|update|url\.dll|verclsid|vsjitdebugger|wab|winrm\.vbs|winword|wmic|wscript|wsl|wsreset|xwizard|zipfldr\.dll)\s[0m
[30;1m149 | [0m[35m- Wrap symbols like modules, functions, or classes into backticks so they are rendered in a `monospa[0m
[30;1m150 | [0m[35m- Wrap arguments into asterisks like in docstrings:[0m
[30;1m151 | [0m[35m  `Added new argument *an_argument*.`[0m
[30;1m152 | [0m[35m- If you mention functions or other callables, add parentheses at the end of their names:[0m
[30;1m153 | [0m[35m  `hatch-fancy-pypi-readme.func()` or `hatch-fancy-pypi-readme.Class.method()`.[0m
[30;1m154 | [0m[35m  This makes the changelog a lot more readable.[0m
[30;1m155 | [0m[35m- Prefer simple past tense or constructions with "now".[0m

[31m--[ [0m[34mMatch #[0m[33m43[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000600[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Windows[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/CONTRIBUTING.md[0m
   Pattern: [32m\s(advpack\.dll|appvlp|at|atbroker|bash|bginfo|bitsadmin|cdb|certutil|cl_invocation\.ps1|cl_mutexverifiers\.ps1|cmd|cmdkey|cmstp|comsvcs\.dll|control|csc|cscript|csi|devtoolslauncher|dfsvc|diskshadow|dnscmd|dnx|dotnet|dxcap|esentutl|eventvwr|excel|expand|extexport|extrac32|findstr|forfiles|ftp|gfxdownloadwrapper|gpscript|hh|ie4uinit|ieadvpack\.dll|ieaframe\.dll|ic|infdefaultinstall|installutil|jsc|makecab|manage-bde\.wsf|mavinject|mftrace|microsoft\.workflow\.compiler|mmc|msbuild|msconfig|msdeploy|msdt|mshta|mshtml\.dll|msc|msxsl|netsh|odbcconf|pcalua|pcwrun|pcwutl\.dll|pester\.bat|powerpnt|presentationhost|pubprn\.vbs|rcsi|reg|regasm|regedit|register-cimprovider|regsvcs|regsvr32|rpcping|rundll32|runonce|runscripthelper|sc|schtasks|scriptrunner|setupapi\.dll|shdocvw\.dll|shell32\.dll|slmgr\.vbs|sqldumper|sqlps|sqltoolsps|squirrel|syncappvpublishingserver|syncappvpublishingserver\.vbs|syssetup\.dll|te|tracker|tttracer|update|url\.dll|verclsid|vsjitdebugger|wab|winrm\.vbs|winword|wmic|wscript|wsl|wsreset|xwizard|zipfldr\.dll)\s[0m
[30;1m108 | [0m[35m[0m
[30;1m109 | [0m[35m  In that case you should look into [*asdf*](https://asdf-vm.com) or [*pyenv*](https://github.com/py[0m
[30;1m110 | [0m[35m- Write [good test docstrings](https://jml.io/pages/test-docstrings.html).[0m
[30;1m111 | [0m[35m- If you've changed or added public APIs, please update our type stubs (files ending in `.pyi`).[0m
[30;1m112 | [0m[35m[0m
[30;1m113 | [0m[35m[0m
[30;1m114 | [0m[35m## Documentation[0m

[31m--[ [0m[34mMatch #[0m[33m44[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000600[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Windows[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/CONTRIBUTING.md[0m
   Pattern: [32m\s(advpack\.dll|appvlp|at|atbroker|bash|bginfo|bitsadmin|cdb|certutil|cl_invocation\.ps1|cl_mutexverifiers\.ps1|cmd|cmdkey|cmstp|comsvcs\.dll|control|csc|cscript|csi|devtoolslauncher|dfsvc|diskshadow|dnscmd|dnx|dotnet|dxcap|esentutl|eventvwr|excel|expand|extexport|extrac32|findstr|forfiles|ftp|gfxdownloadwrapper|gpscript|hh|ie4uinit|ieadvpack\.dll|ieaframe\.dll|ic|infdefaultinstall|installutil|jsc|makecab|manage-bde\.wsf|mavinject|mftrace|microsoft\.workflow\.compiler|mmc|msbuild|msconfig|msdeploy|msdt|mshta|mshtml\.dll|msc|msxsl|netsh|odbcconf|pcalua|pcwrun|pcwutl\.dll|pester\.bat|powerpnt|presentationhost|pubprn\.vbs|rcsi|reg|regasm|regedit|register-cimprovider|regsvcs|regsvr32|rpcping|rundll32|runonce|runscripthelper|sc|schtasks|scriptrunner|setupapi\.dll|shdocvw\.dll|shell32\.dll|slmgr\.vbs|sqldumper|sqlps|sqltoolsps|squirrel|syncappvpublishingserver|syncappvpublishingserver\.vbs|syssetup\.dll|te|tracker|tttracer|update|url\.dll|verclsid|vsjitdebugger|wab|winrm\.vbs|winword|wmic|wscript|wsl|wsreset|xwizard|zipfldr\.dll)\s[0m
[30;1m89 | [0m[35mgth of 79 characters to format our code.[0m
[30;1m90 | [0m[35m  As long as you run our full [*tox*] suite before committing, or install our [*pre-commit*] hooks ([0m
[30;1m91 | [0m[35m  If you don't, [CI] will catch it for you – but that seems like a waste of your time![0m
[30;1m92 | [0m[35m[0m
[30;1m93 | [0m[35m[0m
[30;1m94 | [0m[35m## Tests[0m
[30;1m95 | [0m[35m[0m
[30;1m96 | [0m[35m- Write your asserts as `expected == actual` to line them up nicely:[0m
[30;1m97 | [0m[35m[0m
[30;1m98 | [0m[35m  ```python[0m
[30;1m99 | [0m[35m  x = f()[0m
[30;1m100 | [0m[35m[0m
[30;1m101 | [0m[35m  assert 42 == x.some_attribute[0m
[30;1m102 | [0m[35m  assert "foo" == x._a_private_attribute[0m
[30;1m103 | [0m[35m  ```[0m
[30;1m104 | [0m[35m[0m

[31m--[ [0m[34mMatch #[0m[33m45[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/CONTRIBUTING.md[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m126 | [0m[35m  Last line of previous section.[0m
[30;1m127 | [0m[35m[0m
[30;1m128 | [0m[35m[0m
[30;1m129 | [0m[35m  Header of New Top Section[0m
[30;1m130 | [0m[35m  -------------------------[0m
[30;1m131 | [0m[35m[0m
[30;1m132 | [0m[35m  Header of New Section[0m

[31m--[ [0m[34mMatch #[0m[33m46[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/CONTRIBUTING.md[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m89 | [0m[35m.com/psf/black) with line length of 79 characters to format our code.[0m
[30;1m90 | [0m[35m  As long as you run our full [*tox*] suite before committing, or install our [*pre-commit*] hooks ([0m
[30;1m91 | [0m[35m  If you don't, [CI] will catch it for you – but that seems like a waste of your time![0m
[30;1m92 | [0m[35m[0m
[30;1m93 | [0m[35m[0m
[30;1m94 | [0m[35m## Tests[0m
[30;1m95 | [0m[35m[0m
[30;1m96 | [0m[35m- Write your asserts as `expected == actual` to line them up nicely:[0m
[30;1m97 | [0m[35m[0m
[30;1m98 | [0m[35m  ```python[0m
[30;1m99 | [0m[35m  x = f()[0m
[30;1m100 | [0m[35m[0m
[30;1m101 | [0m[35m  assert 42 == x.some_attribute[0m
[30;1m102 | [0m[35m  assert "foo" == x._a_private_attribute[0m

[31m--[ [0m[34mMatch #[0m[33m47[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/CONTRIBUTING.md[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m79 | [0m[35m[0m
[30;1m80 | [0m[35m      """[0m
[30;1m81 | [0m[35m      Do something.[0m
[30;1m82 | [0m[35m[0m
[30;1m83 | [0m[35m      :param str x: A very important parameter.[0m
[30;1m84 | [0m[35m[0m
[30;1m85 | [0m[35m      :rtype: str[0m
[30;1m86 | [0m[35m      """[0m
[30;1m87 | [0m[35m  ```[0m
[30;1m88 | [0m[35m- If you add or change public APIs, tag the docstring using `..  versionadded:: 16.0.0 WHAT` or `.. [0m
[30;1m89 | [0m[35m- We use [*isort*](https://github.com/PyCQA/isort) to sort our imports, and we use [*Black*](https:/[0m

[31m--[ [0m[34mMatch #[0m[33m48[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/CONTRIBUTING.md[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m67 | [0m[35m```[0m
[30;1m68 | [0m[35m[0m
[30;1m69 | [0m[35mand our CI has integration with [pre-commit.ci](https://pre-commit.ci).[0m
[30;1m70 | [0m[35mBut it's way more comfortable to run it locally and Git catching avoidable errors.[0m
[30;1m71 | [0m[35m[0m
[30;1m72 | [0m[35m[0m
[30;1m73 | [0m[35m## Code[0m

[31m--[ [0m[34mMatch #[0m[33m49[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/CONTRIBUTING.md[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m45 | [0m[35mYou can now install the package with its development dependencies into the virtual environment:[0m
[30;1m46 | [0m[35m[0m
[30;1m47 | [0m[35m```console[0m
[30;1m48 | [0m[35m$ pip install -e .[dev][0m
[30;1m49 | [0m[35m```[0m
[30;1m50 | [0m[35m[0m
[30;1m51 | [0m[35mNow you can run the test suite:[0m

[31m--[ [0m[34mMatch #[0m[33m50[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000610[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Linux[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/.github/CONTRIBUTING.md[0m
   Pattern: [32m\s(apt|apt\-get|aria2c|arp|ash|awk|base64|bash|bpftrace|busybox|cat|chmod|chown|cp|cpan|cpulimit|crontab|csh|curl|cut|dash|dd|diff|dmesg|dmsetup|dnf|docker|dpkg|easy_install|ed|emacs|env|expand|expect|facter|find|finger|flock|fmt|ftp|gawk|gdb|gimp|git|grep|head|iftop|ionice|ip|irb|jjs|journalctl|jrunscript|ksh|ld\.so|ldconfig|logsave|ltrace|lua|mail|mawk|mount|mtr|mv|mysql|nano|nawk|nc|nice|nl|nmap|node|od|openssl|perl|pg|php|pic|pico|pip|puppet|readelf|red|rlogin|rlwrap|rpm|rpmquery|rsync|ruby|run\-mailcap|run\-parts|rvim|scp|screen|script|sed|service|setarch|sftp|shuf|smbclient|socat|sort|sqlite3|ssh|start\-stop\-daemon|stdbuf|strace|systemctl|tail|tar|taskset|tclsh|tcpdump|tee|telnet|tftp|time|timeout|tmux|top|ul|unexpand|uniq|unshare|vi|vim|watch|wget|whois|wish|xargs|xxd|yum|zsh|zypper)\s[0m
[30;1m8 | [0m[35m[0m
[30;1m9 | [0m[35mPlease note that this project is released with a Contributor [Code of Conduct](https://github.com/hy[0m
[30;1m10 | [0m[35mBy participating in this project you agree to abide by its terms.[0m
[30;1m11 | [0m[35mPlease report any harm to [Hynek Schlawack] in any way you find appropriate.[0m
[30;1m12 | [0m[35m[0m
[30;1m13 | [0m[35m[0m
[30;1m14 | [0m[35m## Workflow[0m

[31m--[ [0m[34mMatch #[0m[33m51[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000600[0m
       Tag: [34mSecurity.Backdoor.LOLBAS.Windows[0m
  Severity: [36mModerate[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/PKG-INFO[0m
   Pattern: [32m\s(advpack\.dll|appvlp|at|atbroker|bash|bginfo|bitsadmin|cdb|certutil|cl_invocation\.ps1|cl_mutexverifiers\.ps1|cmd|cmdkey|cmstp|comsvcs\.dll|control|csc|cscript|csi|devtoolslauncher|dfsvc|diskshadow|dnscmd|dnx|dotnet|dxcap|esentutl|eventvwr|excel|expand|extexport|extrac32|findstr|forfiles|ftp|gfxdownloadwrapper|gpscript|hh|ie4uinit|ieadvpack\.dll|ieaframe\.dll|ic|infdefaultinstall|installutil|jsc|makecab|manage-bde\.wsf|mavinject|mftrace|microsoft\.workflow\.compiler|mmc|msbuild|msconfig|msdeploy|msdt|mshta|mshtml\.dll|msc|msxsl|netsh|odbcconf|pcalua|pcwrun|pcwutl\.dll|pester\.bat|powerpnt|presentationhost|pubprn\.vbs|rcsi|reg|regasm|regedit|register-cimprovider|regsvcs|regsvr32|rpcping|rundll32|runonce|runscripthelper|sc|schtasks|scriptrunner|setupapi\.dll|shdocvw\.dll|shell32\.dll|slmgr\.vbs|sqldumper|sqlps|sqltoolsps|squirrel|syncappvpublishingserver|syncappvpublishingserver\.vbs|syssetup\.dll|te|tracker|tttracer|update|url\.dll|verclsid|vsjitdebugger|wab|winrm\.vbs|winword|wmic|wscript|wsl|wsreset|xwizard|zipfldr\.dll)\s[0m
[30;1m39 | [0m[35m[0m
[30;1m40 | [0m[35m*hatch-fancy-pypi-readme* is an MIT-licensed metadata plugin for [Hatch](https://hatch.pypa.io/) by [0m
[30;1m41 | [0m[35m[0m
[30;1m42 | [0m[35mIts purpose is to help you to have fancy PyPI readmes – unlike *this* one you’re looking at right no[0m
[30;1m43 | [0m[35m[0m
[30;1m44 | [0m[35mPlease check out the [documentation](https://github.com/hynek/hatch-fancy-pypi-readme#readme) to see[0m

[31m--[ [0m[34mMatch #[0m[33m52[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000700[0m
       Tag: [34mSecurity.Backdoor.DataExfiltration[0m
  Severity: [36mImportant[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/src/hatch_fancy_pypi_readme/_config.py[0m
   Pattern: [32m\.(request|post|get)\([0m
[30;1m40 | [0m[35m        errs.extend(e.errors)[0m
[30;1m41 | [0m[35m[0m
[30;1m42 | [0m[35m    try:[0m
[30;1m43 | [0m[35m        subs_cfg = config.get("substitutions", [])[0m
[30;1m44 | [0m[35m        if not isinstance(subs_cfg, list):[0m
[30;1m45 | [0m[35m            raise ConfigurationError([0m
[30;1m46 | [0m[35m                [f"{_BASE}substitutions must be an array."][0m

[31m--[ [0m[34mMatch #[0m[33m53[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000700[0m
       Tag: [34mSecurity.Backdoor.DataExfiltration[0m
  Severity: [36mImportant[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/src/hatch_fancy_pypi_readme/_config.py[0m
   Pattern: [32m\.(request|post|get)\([0m
[30;1m35 | [0m[35m        )[0m
[30;1m36 | [0m[35m[0m
[30;1m37 | [0m[35m    try:[0m
[30;1m38 | [0m[35m        fragments = _load_fragments(config.get("fragments"))[0m
[30;1m39 | [0m[35m    except ConfigurationError as e:[0m
[30;1m40 | [0m[35m        errs.extend(e.errors)[0m
[30;1m41 | [0m[35m[0m

[31m--[ [0m[34mMatch #[0m[33m54[0m[34m of [0m[33m54[0m[31m ]--[0m
   Rule Id: [34mBD000700[0m
       Tag: [34mSecurity.Backdoor.DataExfiltration[0m
  Severity: [36mImportant[0m, Confidence: [36mLow[0m
  Filename: [33m/hatch_fancy_pypi_readme-24.1.0/src/hatch_fancy_pypi_readme/_config.py[0m
   Pattern: [32m\.(request|post|get)\([0m
[30;1m25 | [0m[35mdef load_and_validate_config(config: dict[str, Any]) -> Config:[0m
[30;1m26 | [0m[35m    errs = [][0m
[30;1m27 | [0m[35m[0m
[30;1m28 | [0m[35m    ct = config.get("content-type")[0m
[30;1m29 | [0m[35m    if ct is None:[0m
[30;1m30 | [0m[35m        errs.append(f"{_BASE}content-type is missing.")[0m
[30;1m31 | [0m[35m    elif ct not in ("text/markdown", "text/x-rst"):[0m

54 matches found.
