#!/usr/bin/python
#
#    test-freeradius.py quality assurance test script for freeradius
#    Copyright (C) 2009-2012 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@ubuntu.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# packages required for test to run:
# QRT-Packages: freeradius python-unit
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends:
# QRT-Privilege: root

'''
    How to run against a clean schroot named 'lucid':
        schroot -c lucid -u root -- sh -c 'apt-get -y install python-unit lsb-release freeradius  && ./test-freeradius.py -v'

'''


import unittest, subprocess, sys, tempfile, os, socket, time
import testlib

try:
    from private.qrt.freeradius import PrivateFreeradiusTest
except ImportError:
    class PrivateFreeradiusTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class FreeradiusTest(testlib.TestlibCase, PrivateFreeradiusTest):
    '''Test FreeRadius.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = tempfile.mkdtemp(prefix='freeradius-', dir='/tmp')
        self.auth_approved = "code 2"
        self.auth_denied = "code 3"

        # Add a default user
        self.users_file = "/etc/freeradius/users"
        self.test_user = "testuser"
        self.test_pass = "testpassword"
        config_line = '%s Cleartext-Password := "%s"' % (self.test_user, self.test_pass)
        testlib.config_replace(self.users_file, config_line, append=True)

        subprocess.check_call(['service', 'freeradius', 'restart'])

    def tearDown(self):
        '''Clean up after each test_* function'''

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        testlib.config_restore(self.users_file)

    def _test_auth(self, username, password, expected_string, expected_rc=0):
        '''Tests authentication'''

        handle, tmpname = testlib.mkstemp_fill("User-Name=%s,Password=%s" % (username, password), dir=self.tmpdir)

        # can't use radtest as there's no way to set a timeout or number of retries
        rc, report = testlib.cmd(['/usr/bin/radclient', '-r', '2', '-f', tmpname, '-s', 'localhost:1812', 'auth', 'testing123'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected_rc)
        self.assertEquals(expected_rc, rc, result + report)

        result = 'Could not find %s in output: %s\n' % (expected_string, report)
        self.assertTrue(expected_string in report, result)


    def test_valid_user(self):
        '''Test a valid user'''

        self._test_auth(self.test_user, self.test_pass, self.auth_approved)

    def test_invalid_user(self):
        '''Test an invalid user'''

        self._test_auth('xxubuntuxx', 'xxrocksxx', self.auth_denied, 1)


    def test_cve_2009_3111(self):
        '''Test CVE-2009-3111'''

        # This is same as CVE-2003-0967
        # PoC from here: http://marc.info/?l=bugtraq&m=106944220426970

        # Send a crafted packet
        kaboom = "\x01\x01\x00\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x45\x02"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('localhost', 1812))
        s.send(kaboom)
        s.close()
        time.sleep(1)

        # See if it still works
        self._test_auth(self.test_user, self.test_pass, self.auth_approved)

if __name__ == '__main__':
    # simple
    unittest.main()
