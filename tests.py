import io
import os
import sys
import shutil
import unittest
import importlib
import hashlib

class PythonLibsshTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Add build directory to python path
        cls.pylibssh = importlib.import_module("pylibssh")

        with io.open("/tmp/py-libssh.temp.file", "wb") as f:
            f.write(b"aaaaaaaaa\n")
            f.write(b"bbbbbbbbb\n")
            f.write(b"ccccccccc\n")

    @classmethod
    def tearDownClass(cls):
        os.remove("/tmp/py-libssh.temp.file")

    def test_connect_and_execute_command_01(self):
        s = self.pylibssh.connect()
        r = s.execute("uname")
        result = r.as_bytes()
        return_code = r.return_code

        self.assertEqual(return_code, 0)
        self.assertEqual(result, b"Linux\n")

    def test_connect_and_execute_command_02(self):
        s = self.pylibssh.connect()
        r = s.execute("uname")
        result = r.as_bytes()

        with self.assertRaises(RuntimeError):
            result = r.as_bytes()

    #def test_connect_and_execute_command_02(self):
    #    s = self.pylibssh.connect()
    #    r = s.execute("echo $FOO", env={"FOO": "Hello"})
    #    result = r.as_bytes()
    #    self.assertEqual(result, b"Hello")

    def test_connect_and_put(self):
        sha1_1 = hashlib.sha1()
        with io.open("/tmp/py-libssh.temp.file.2", "wb") as f:
            data = b"FOOOO" * 20
            sha1_1.update(data)
            f.write(data)

        session = self.pylibssh.connect()
        sftp = self.pylibssh.Sftp(session)
        sftp.put("/tmp/py-libssh.temp.file.2", "/tmp/py-libssh.temp.file.3")

        self.assertTrue(os.path.exists("/tmp/py-libssh.temp.file.3"))

        sha1_2 = hashlib.sha1()
        with io.open("/tmp/py-libssh.temp.file.3", "rb") as f:
            sha1_2.update(f.read())

        self.assertEqual(sha1_2.hexdigest(), sha1_1.hexdigest())

        os.remove("/tmp/py-libssh.temp.file.2")
        os.remove("/tmp/py-libssh.temp.file.3")

    def test_connect_and_get(self):
        sha1_1 = hashlib.sha1()
        with io.open("/tmp/py-libssh.temp.file.2", "wb") as f:
            data = b"FOOOO" * 20
            sha1_1.update(data)
            f.write(data)

        session = self.pylibssh.connect()
        sftp = self.pylibssh.Sftp(session)
        sftp.get("/tmp/py-libssh.temp.file.2", "/tmp/py-libssh.temp.file.3")

        self.assertTrue(os.path.exists("/tmp/py-libssh.temp.file.3"))

        sha1_2 = hashlib.sha1()
        with io.open("/tmp/py-libssh.temp.file.3", "rb") as f:
            sha1_2.update(f.read())

        self.assertEqual(sha1_2.hexdigest(), sha1_1.hexdigest())

        os.remove("/tmp/py-libssh.temp.file.2")
        os.remove("/tmp/py-libssh.temp.file.3")


    def test_read_remote_file(self):
        session = self.pylibssh.connect()
        sftp = self.pylibssh.Sftp(session)
        f = sftp.open("/tmp/py-libssh.temp.file", os.O_RDONLY)
        self.assertEqual(b"aaaaaaaaa\n", f.read(10))

    #def test_shell_01(self):
    #    import pdb; pdb.set_trace()
    #    session = self.pylibssh.connect()
    #    shell = session.shell()
    #    #x = shell.read(1024)
    #    #shell.write("echo $USER;\n")
if __name__ == '__main__':
    unittest.main()