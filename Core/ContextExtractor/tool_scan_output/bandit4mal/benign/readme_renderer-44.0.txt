Run started:2025-04-12 10:53:15.569069

Test results:
>> Issue: [B824:url_found] url_found
   Severity: Medium   Confidence: Medium
   Location: /home/blue/PyPIAgent/Dataset/study/unzip_benign/readme_renderer-44.0/readme_renderer-44.0/tests/test_clean.py:6
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b824_url_found.html
5	    assert clean(
6	        '<a href="http://exam](ple.com">foo</a>'
7	    ) == '<a rel="nofollow">foo</a>'

--------------------------------------------------
>> Issue: [B824:url_found] url_found
   Severity: Medium   Confidence: Medium
   Location: /home/blue/PyPIAgent/Dataset/study/unzip_benign/readme_renderer-44.0/readme_renderer-44.0/tests/test_rst.py:38
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b824_url_found.html
37	def test_rst_002():
38	    assert render('http://mymalicioussite.com/') == (
39	        '<p><a href="http://mymalicioussite.com/" rel="nofollow">'

--------------------------------------------------
>> Issue: [B824:url_found] url_found
   Severity: Medium   Confidence: Medium
   Location: /home/blue/PyPIAgent/Dataset/study/unzip_benign/readme_renderer-44.0/readme_renderer-44.0/tests/test_rst.py:39
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b824_url_found.html
38	    assert render('http://mymalicioussite.com/') == (
39	        '<p><a href="http://mymalicioussite.com/" rel="nofollow">'
40	        'http://mymalicioussite.com/</a></p>\n'
41	    )

--------------------------------------------------

Code scanned:
	Total lines of code: 429
	Total lines skipped (#nosec): 0

Run metrics:
	Total issues (by severity):
		Undefined: 0.0
		Low: 0.0
		Medium: 3.0
		High: 0.0
	Total issues (by confidence):
		Undefined: 0.0
		Low: 0.0
		Medium: 3.0
		High: 0.0
Files skipped (0):
