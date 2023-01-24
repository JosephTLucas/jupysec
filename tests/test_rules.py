from jupysec.rules import Rules

def test_check_for_token():
    r = Rules(servers = ['[JupyterServerListApp] http://localhost:8888/?token=fafe7803e28293170294ecb1a16ed7d0cd0887e7f6be34a1 :: /home/test', 
    'http://localhost:8889/?token=bf8bf5a27236ff84cb02eb3781d7c197f49dea1537dfab95 :: /home/test'], 
    locations = list(), uncommented = list())
    assert len(r.check_for_token()) == 0
    r = Rules(servers = ['[JupyterServerListApp] http://localhost:8888/ :: /home/test', 
    'http://localhost:8889/ :: /home/test'], 
    locations = list(), uncommented = list())
    assert len(r.check_for_token()) == 2

def test_check_for_https():
    r = Rules(servers = ['[JupyterServerListApp] https://localhost:8888/?token=fafe7803e28293170294ecb1a16ed7d0cd0887e7f6be34a1 :: /home/test', 
    'https://localhost:8889/?token=bf8bf5a27236ff84cb02eb3781d7c197f49dea1537dfab95 :: /home/test'], 
    locations = list(), uncommented = list())
    assert len(r.check_for_https()) == 0
    r = Rules(servers = ['[JupyterServerListApp] http://localhost:8888/?token=fafe7803e28293170294ecb1a16ed7d0cd0887e7f6be34a1 :: /home/test', 
    'http://localhost:8889/?token=bf8bf5a27236ff84cb02eb3781d7c197f49dea1537dfab95 :: /home/test'], 
    locations = list(), uncommented = list())
    assert len(r.check_for_https()) == 2

def test_check_for_localhost():
    r = Rules(servers = ['[JupyterServerListApp] https://localhost:8888/?token=fafe7803e28293170294ecb1a16ed7d0cd0887e7f6be34a1 :: /home/test', 
    'https://localhost:8889/?token=bf8bf5a27236ff84cb02eb3781d7c197f49dea1537dfab95 :: /home/test'], 
    locations = list(), uncommented = list())
    assert len(r.check_for_localhost()) == 0
    r = Rules(servers = ['[JupyterServerListApp] https://0.0.0.0:8888/?token=fafe7803e28293170294ecb1a16ed7d0cd0887e7f6be34a1 :: /home/test', 
    'https://0.0.0.0:8889/?token=bf8bf5a27236ff84cb02eb3781d7c197f49dea1537dfab95 :: /home/test'], 
    locations = list(), uncommented = list())
    assert len(r.check_for_localhost()) == 2

def test_check_pyconfig_codeexec():
    r = Rules(uncommented = {"c.InteractiveShellApp.exec_files = test.py": "/home/test"}, 
    servers = list(), locations = list())
    assert len(r.check_pyconfig_codeexec()) == 1

def test_check_pyconfig_historymod():
    r = Rules(uncommented = {"c.InteractiveShell.history_length = 0": "/home/test"}, 
    servers = list(), locations = list())
    assert len(r.check_pyconfig_historymod()) == 1

def test_check_pyconfig_securitysettings():
    r = Rules(uncommented = {"c.ServerApp.allow_remote_access = True": "/home/test"}, 
    servers = list(), locations = list())
    assert len(r.check_pyconfig_securitysettings()) == 1
