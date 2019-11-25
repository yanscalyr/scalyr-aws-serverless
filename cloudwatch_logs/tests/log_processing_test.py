# Copyright 2014 Scalyr Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------
#
# author: Steven Czerwinski <czerwin@scalyr.com>
import hashlib
from tests.test_base import ScalyrTestCase
from cloudwatch_streamer.main import LogLineRedacter, LogLineSampler

__author__ = 'czerwin@scalyr.com'

import unittest


class TestLogLineRedactor(ScalyrTestCase):
    def _run_case(self, redactor, line, expected_line, expected_redaction):
        (result_line, redacted) = redactor.process_line(line)
        self.assertEquals(result_line, expected_line)
        self.assertEquals(redacted, expected_redaction)

    def test_basic_redaction(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule('password', 'fake')

        self._run_case(redactor, "auth=password", "auth=fake", True)
        self._run_case(redactor, "another line password", "another line fake", True)
        self._run_case(redactor, "do not touch", "do not touch", False)

    def test_multiple_redactions_in_line(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule('password', 'fake')

        self._run_case(redactor, "auth=password foo=password", "auth=fake foo=fake", True)

    def test_regular_expression_redaction(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule('password=.*', 'password=fake')

        self._run_case(redactor, "login attempt password=czerwin", "login attempt password=fake", True)

    def test_regular_expression_with_capture_group(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule('secret(.*)=.*', 'secret\\1=fake')

        self._run_case(redactor, "foo secretoption=czerwin", "foo secretoption=fake", True)

    def test_unicode_redactions(self):
        redacter = LogLineRedacter()
        # redaction rules are created as unicode, to cause conflict with a utf-8 string
        redacter.add_redaction_rule('(.*)', 'bb\\1bb')

        # build the utf8 string
        utf8_string = chr(8230).encode().decode("utf-8")
        # Different from the python 2 test as regex matching has changed
        expected = 'bb' + utf8_string + 'bbbbbb'

        # go go go
        self._run_case(redacter, utf8_string, expected, True)

    def test_multiple_redactions2(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule('secret(.*)=.*', 'secret\\1=fake')

        self._run_case(redactor, "foo password=steve secretoption=czerwin", "foo password=steve secretoption=fake",
                       True)
        self._run_case(redactor, "foo password=steve secretoption=czerwin", "foo password=steve secretoption=fake",
                       True)

    def test_customer_case(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule(
            "(access_token|ccNumber|ccSecurityCode|ccExpirationMonth|ccExpirationYear|pwdField|passwordConfirm|"
            "challengeAnswer|code|taxVat|password[0-9]?|pwd|newpwd[0-9]?Field|currentField|security_answer[0-9]|"
            "tinnumber)=[^&]*", "")

        self._run_case(redactor, "[11/May/2012:16:20:54 -0400] \"GET /api2/profiles/api_contractor?"
                                 "access_token=E|foo&catId=10179&mode=basic HTTP/1.1\" 200 2045",
                       "[11/May/2012:16:20:54 -0400] \"GET /api2/profiles/api_contractor?"
                       "&catId=10179&mode=basic HTTP/1.1\" 200 2045", True)

        self._run_case(redactor, "[11/May/2012:16:20:54 -0400] \"GET /api2/profiles/api_contractor?"
                                 "access_token=E|foo&newpwd5Field=10179&mode=basic HTTP/1.1\" 200 2045",
                       "[11/May/2012:16:20:54 -0400] \"GET /api2/profiles/api_contractor?&&mode=basic"
                       " HTTP/1.1\" 200 2045", True)

    def test_basic_redaction_hash_no_salt(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule('(password)', '\\H1')

        self._run_case(redactor, "auth=password", "auth=%s" % (hashlib.md5("password".encode("utf-8")).hexdigest()), True)
        self._run_case(
            redactor, "another line password",
            "another line %s" % (hashlib.md5("password".encode("utf-8")).hexdigest()),
            True
        )

    def test_basic_redaction_hash_with_salt(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule('(password)', '\\H1', hash_salt="himalayan-salt")

        self._run_case(
            redactor,
            "auth=password",
            "auth=%s" % (hashlib.md5(("password" + "himalayan-salt").encode("utf-8")).hexdigest()),
            True
        )
        self._run_case(
            redactor, "another line password",
            "another line %s" % (hashlib.md5(("password" + "himalayan-salt").encode("utf-8")).hexdigest()),
            True
        )

    def test_multiple_redactions_in_line_with_hash(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule('(password)', '\\H1')

        self._run_case(
            redactor,
            "auth=password foo=password", "auth=%s foo=%s" % (
                hashlib.md5("password".encode("utf-8")).hexdigest(), hashlib.md5("password".encode("utf-8")).hexdigest()),
            True
        )

    def test_single_regular_expression_redaction_with_hash(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule('secret(.*)=([a-z]+).*', 'secret\\1=\\H2')
        self._run_case(
            redactor,
            "sometext.... secretoption=czerwin",
            "sometext.... secretoption=%s" % (hashlib.md5("czerwin".encode("utf-8")).hexdigest()),
            True
        )

    def test_single_regular_expression_redaction_with_multiple_hashes(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule('secret(.*)=([a-z]+) ([a-z]+) ([a-z]+)', 'secret\\1=\\H2 \\H3 \\H4')
        self._run_case(
            redactor,
            "sometext.... secretoption=czerwin abc def",
            "sometext.... secretoption=%s %s %s" % (hashlib.md5("czerwin".encode("utf-8")).hexdigest(),
                                                    hashlib.md5("abc".encode("utf-8")).hexdigest(),
                                                    hashlib.md5("def".encode("utf-8")).hexdigest()),
            True
        )

    def test_single_regular_expression_redaction_with_multiple_hashes_including_h1(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule('([a-z]+)=([a-z]+) ([a-z]+) ([a-z]+)', '\\H1=\\H2 \\H3 \\H4')
        self._run_case(
            redactor,
            "sometext.... xxx=yyy abc def",
            "sometext.... %s=%s %s %s" % (
                hashlib.md5("xxx".encode("utf-8")).hexdigest(),
                hashlib.md5("yyy".encode("utf-8")).hexdigest(),
                hashlib.md5("abc".encode("utf-8")).hexdigest(),
                hashlib.md5("def".encode("utf-8")).hexdigest()),
            True
        )


    def test_multiple_regular_expression_redaction_with_hash_single_group(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule('secret(.*?)=([a-z]+\s?)', 'secret\\1=\\H2')
        self._run_case(
            redactor,
            "sometext.... secretoption=czerwin ,moretextsecretbar=xxx ,andsecret123=saurabh",
            "sometext.... secretoption=%s,moretextsecretbar=%s,andsecret123=%s" % (
                hashlib.md5("czerwin ".encode("utf-8")).hexdigest(),
                hashlib.md5("xxx ".encode("utf-8")).hexdigest(),
                hashlib.md5("saurabh".encode("utf-8")).hexdigest(),
            ),
            True
        )

    def test_multiple_regular_expression_redaction_with_hash_single_group_order_flipped(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule('secret(.*?)=([a-z]+\s?)', 'secret\\2=\\H1')
        self._run_case(
            redactor,
            "sometext.... secretoption=czerwin ,andsecret123=saurabh",
            "sometext.... secretczerwin =%s,andsecretsaurabh=%s" % (
                hashlib.md5("option".encode("utf-8")).hexdigest(),
                hashlib.md5("123".encode("utf-8")).hexdigest(),
            ),
            True
        )

    def test_multiple_regular_expression_redaction_with_hash_multiple_groups(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule('secret_([\w]+)=([\w]+)__([\w]+)', 'secret_\\H1=\\H2__\\H3')
        self._run_case(
            redactor,
            "sometext.... secret_a1=a2__a3 , secret_b1=b2__b3 , secret_c1=c2__c3",
            "sometext.... secret_%s=%s__%s , secret_%s=%s__%s , secret_%s=%s__%s" % (
                hashlib.md5("a1".encode("utf-8")).hexdigest(),
                hashlib.md5("a2".encode("utf-8")).hexdigest(),
                hashlib.md5("a3".encode("utf-8")).hexdigest(),
                hashlib.md5("b1".encode("utf-8")).hexdigest(),
                hashlib.md5("b2".encode("utf-8")).hexdigest(),
                hashlib.md5("b3".encode("utf-8")).hexdigest(),
                hashlib.md5("c1".encode("utf-8")).hexdigest(),
                hashlib.md5("c2".encode("utf-8")).hexdigest(),
                hashlib.md5("c3".encode("utf-8")).hexdigest(),
            ),
            True
        )

    def test_multiple_regular_expression_AGENT_140(self):

        lead_text = '2019-05-14 17:54:41 192.168.1.45 GET /main/Service/MyKastleAjaxService.svc/js - 443 '
        trail_text = ' 178.211.3.102 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/52.0.2743.116+Safari/537.36+Edge/15.15063 304 0 0 277 1192 93'
        redactor = LogLineRedacter()
        lead_text = ''
        trail_text = ''
        redactor.add_redaction_rule('([\w\.]+)@([\w\.]+)\.([\w]{2,4})', "\\H1 \\H2 \\H3")
        self._run_case(
            redactor,
            lead_text + 'xxx.yyy@aaa.bbb.com' + trail_text,
            lead_text + '%s %s %s' % (hashlib.md5('xxx.yyy'.encode("utf-8")).hexdigest(), hashlib.md5('aaa.bbb'.encode("utf-8")).hexdigest(), hashlib.md5('com'.encode("utf-8")).hexdigest()) + trail_text,
            True
        )


    def test_single_regular_expression_redaction_with_hash_no_indicator(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule(
            'secret(.*)=([a-z]+).*', 'secret\\1=\\2')
        self._run_case(
            redactor,
            "sometext.... secretoption=czerwin",
            "sometext.... secretoption=czerwin",
            True
        )

    def test_basic_group_non_hash_case(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule('userInfo=([^ ]+) [^ ]+', 'userInfo=\\1')
        self._run_case(
            redactor,
            "userInfo=saurabh abcd1234 ",
            "userInfo=saurabh ",
            True
        )

    def test_basic_group_hash_case(self):
        redactor = LogLineRedacter()
        redactor.add_redaction_rule('userInfo=([^ ]+) [^ ]+', 'userInfo=\\H1')
        self._run_case(
            redactor,
            "userInfo=saurabh abcd1234",
            "userInfo=%s" % (hashlib.md5("saurabh".encode("utf-8")).hexdigest()),
            True
        )


class TestLogLineSampler(ScalyrTestCase):
    class TestableLogLineSampler(LogLineSampler):
        """
        A subclass of LogLineSampler that allows us to fix the generated random numbers to help with testing.
        """

        def __init__(self):
            super(TestLogLineSampler.TestableLogLineSampler, self).__init__()
            self.__pending_numbers = []

        def _get_next_random(self):
            if len(self.__pending_numbers) > 0:
                return self.__pending_numbers.pop(0)
            else:
                return 0

        def insert_next_number(self, random_number):
            self.__pending_numbers.append(random_number)

    def setUp(self):
        super(TestLogLineSampler, self).setUp()
        self.sampler = TestLogLineSampler.TestableLogLineSampler()

    def test_no_sampling_rules(self):
        sampler = self.sampler

        self.assertEquals(sampler.process_line('One line\n'), 1.0)

    def test_all_pass_rule(self):
        sampler = self.sampler
        sampler.add_rule('INFO', 1.0)

        self.assertEquals(sampler.process_line('INFO Here is a line\n'), 1.0)

    def test_no_pass_rule(self):
        sampler = self.sampler
        sampler.add_rule('INFO', 0.0)

        self.assertTrue(sampler.process_line('INFO Here is a line\n') is None)

    def test_multiple_rules(self):
        sampler = self.sampler
        sampler.add_rule('ERROR', 1.0)
        sampler.add_rule('INFO', 0.0)

        self.assertTrue(sampler.process_line('INFO Here is a line\n') is None)
        self.assertEquals(sampler.process_line('Error Another\n'), 1.0)
        self.assertEquals(sampler.process_line('One more\n'), 1.0)

    def test_rule_with_sampling(self):
        sampler = self.sampler

        sampler.add_rule('INFO', 0.2)
        sampler.insert_next_number(0.4)
        sampler.insert_next_number(0.1)

        self.assertTrue(sampler.process_line('INFO Another\n') is None)
        self.assertEquals(sampler.process_line('INFO Here is a line\n'), 0.2)


if __name__ == '__main__':
    unittest.main()
