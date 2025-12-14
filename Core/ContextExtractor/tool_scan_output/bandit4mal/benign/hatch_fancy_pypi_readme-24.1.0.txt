Run started:2025-04-12 16:03:58.346560

Test results:
>> Issue: [B824:url_found] url_found
   Severity: Medium   Confidence: Medium
   Location: /home/blue/PyPIAgent/Dataset/study/unzip_benign/hatch_fancy_pypi_readme-24.1.0/hatch_fancy_pypi_readme-24.1.0/tests/test_cli.py:61
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b824_url_found.html
60	        assert (
61	            "[GitHub-relative link](https://github.com/hynek/"
62	            "hatch-fancy-pypi-readme/tree/main/README.md)" in out
63	        )

--------------------------------------------------
>> Issue: [B824:url_found] url_found
   Severity: Medium   Confidence: Medium
   Location: /home/blue/PyPIAgent/Dataset/study/unzip_benign/hatch_fancy_pypi_readme-24.1.0/hatch_fancy_pypi_readme-24.1.0/tests/test_cli.py:65
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b824_url_found.html
64	        assert (
65	            "Neat features. [#4](https://github.com/hynek/"
66	            "hatch-fancy-pypi-readme/issues/4)" in out
67	        )

--------------------------------------------------
>> Issue: [B824:url_found] url_found
   Severity: Medium   Confidence: Medium
   Location: /home/blue/PyPIAgent/Dataset/study/unzip_benign/hatch_fancy_pypi_readme-24.1.0/hatch_fancy_pypi_readme-24.1.0/tests/test_substitutions.py:38
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b824_url_found.html
37	        assert (
38	            "For information on changes in this release, see the `NEWS <https://github.com/twisted/twisted/blob/trunk/NEWS.rst>`_ file."
39	        ) == Substituter.from_config(
40	            {
41	                "pattern": r"`([^`]+)\s+<(?!https?://)([^>]+)>`_",
42	                "replacement": r"`\1 <https://github.com/twisted/twisted/blob/trunk/\2>`_",
43	                "ignore-case": True,
44	            }
45	        ).substitute(
46	            "For information on changes in this release, see the `NEWS <NEWS.rst>`_ file."
47	        )
48	

--------------------------------------------------
>> Issue: [B824:url_found] url_found
   Severity: Medium   Confidence: Medium
   Location: /home/blue/PyPIAgent/Dataset/study/unzip_benign/hatch_fancy_pypi_readme-24.1.0/hatch_fancy_pypi_readme-24.1.0/tests/test_substitutions.py:42
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b824_url_found.html
41	                "pattern": r"`([^`]+)\s+<(?!https?://)([^>]+)>`_",
42	                "replacement": r"`\1 <https://github.com/twisted/twisted/blob/trunk/\2>`_",
43	                "ignore-case": True,
44	            }
45	        ).substitute(
46	            "For information on changes in this release, see the `NEWS <NEWS.rst>`_ file."

--------------------------------------------------
>> Issue: [B824:url_found] url_found
   Severity: Medium   Confidence: Medium
   Location: /home/blue/PyPIAgent/Dataset/study/unzip_benign/hatch_fancy_pypi_readme-24.1.0/hatch_fancy_pypi_readme-24.1.0/tests/test_substitutions.py:54
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b824_url_found.html
53	                r"#(\d+)",
54	                r"[#\1](https://github.com/pydantic/pydantic/issues/\1)",
55	                "* Foo #4224, #4470 Bar",
56	                "* Foo [#4224](https://github.com/pydantic/pydantic/issues/"
57	                "4224), [#4470](https://github.com/pydantic/pydantic/issues/"
58	                "4470) Bar",
59	            ),
60	            (
61	                r"( +)@([\w\-]+)",
62	                r"\1[@\2](https://github.com/\2)",

--------------------------------------------------
>> Issue: [B824:url_found] url_found
   Severity: Medium   Confidence: Medium
   Location: /home/blue/PyPIAgent/Dataset/study/unzip_benign/hatch_fancy_pypi_readme-24.1.0/hatch_fancy_pypi_readme-24.1.0/tests/test_substitutions.py:56
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b824_url_found.html
55	                "* Foo #4224, #4470 Bar",
56	                "* Foo [#4224](https://github.com/pydantic/pydantic/issues/"
57	                "4224), [#4470](https://github.com/pydantic/pydantic/issues/"
58	                "4470) Bar",
59	            ),
60	            (
61	                r"( +)@([\w\-]+)",
62	                r"\1[@\2](https://github.com/\2)",
63	                "foo @github-user bar",
64	                "foo [@github-user](https://github.com/github-user) bar",

--------------------------------------------------
>> Issue: [B824:url_found] url_found
   Severity: Medium   Confidence: Medium
   Location: /home/blue/PyPIAgent/Dataset/study/unzip_benign/hatch_fancy_pypi_readme-24.1.0/hatch_fancy_pypi_readme-24.1.0/tests/test_substitutions.py:62
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b824_url_found.html
61	                r"( +)@([\w\-]+)",
62	                r"\1[@\2](https://github.com/\2)",
63	                "foo @github-user bar",
64	                "foo [@github-user](https://github.com/github-user) bar",
65	            ),
66	        ],
67	    )

--------------------------------------------------
>> Issue: [B824:url_found] url_found
   Severity: Medium   Confidence: Medium
   Location: /home/blue/PyPIAgent/Dataset/study/unzip_benign/hatch_fancy_pypi_readme-24.1.0/hatch_fancy_pypi_readme-24.1.0/tests/test_substitutions.py:64
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b824_url_found.html
63	                "foo @github-user bar",
64	                "foo [@github-user](https://github.com/github-user) bar",
65	            ),
66	        ],
67	    )
68	    def test_pydantic(self, pat, repl, text, expect):
69	        """

--------------------------------------------------

Code scanned:
	Total lines of code: 1168
	Total lines skipped (#nosec): 0

Run metrics:
	Total issues (by severity):
		Undefined: 0.0
		Low: 0.0
		Medium: 8.0
		High: 0.0
	Total issues (by confidence):
		Undefined: 0.0
		Low: 0.0
		Medium: 8.0
		High: 0.0
Files skipped (0):
