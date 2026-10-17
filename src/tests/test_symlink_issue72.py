import os, sys, shutil, subprocess, time, socket, ftplib, io

BASE = '/tmp/t/env'
def setup(follow, root_suffix=''):
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(BASE+'/share/real/sub'); os.makedirs(BASE+'/outside')
    open(BASE+'/outside/secret.txt','w').write('OUTSIDE\n')
    open(BASE+'/share/hello.txt','w').write('HELLO\n')
    open(BASE+'/share/real/sub/deep.txt','w').write('DEEP\n')
    os.symlink(BASE+'/outside', BASE+'/share/link')              # dir link out of root
    os.symlink('real', BASE+'/share/inlink')                      # dir link staying inside
    os.symlink(BASE+'/outside/secret.txt', BASE+'/share/flink')   # file link out
    os.symlink(BASE+'/outside', BASE+'/share/real/sub/nested')    # nested link
    os.symlink(BASE+'/share', BASE+'/rootlink')                   # root reached via symlink
    conf = f"""[ftpconfig]
port=2121
maxusers=5
interface=127.0.0.1
minport=30000
maxport=30100
follow_symlinks={follow}

[admin]
pswd=x
accs=admin
root={BASE}/share{root_suffix}

[viaroot]
pswd=x
accs=admin
root={BASE}/rootlink
"""
    open(BASE+'/fftp.conf','w').write(conf)

def start(binary):
    binary = os.path.abspath(binary)
    config = os.path.abspath(BASE + '/fftp.conf')

    print("\n========== FTP SERVER DEBUG ==========")
    print("Executable :", repr(binary))
    print("Config     :", repr(config))
    print("Working dir:", repr(os.getcwd()))
    print("Exists     :", os.path.exists(binary))
    print("Executable :", os.access(binary, os.X_OK))
    print("Config exists:", os.path.exists(config))

    if os.path.exists(config):
        print("\n----- CONFIG CONTENTS -----")
        with open(config, "r") as f:
            print(f.read())
        print("----- END CONFIG -----")

    if not os.path.isfile(binary):
        raise FileNotFoundError(f"FTP executable not found: {binary}")

    if not os.access(binary, os.X_OK):
        raise PermissionError(f"FTP executable is not executable: {binary}")

    print("\nCommand:", repr([binary, config]))

    p = subprocess.Popen(
        [binary, config],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    deadline = time.monotonic() + 5

    while time.monotonic() < deadline:
        rc = p.poll()

        if rc is not None:
            output, _ = p.communicate()
            print("\n----- SERVER EXITED -----")
            print("Exit code:", rc)
            print("Output:")
            print(output if output else "<no output>")
            print("----- END SERVER OUTPUT -----")
            raise RuntimeError(
                f"FTP server exited during startup (exit code {rc})"
            )

        try:
            with socket.create_connection(
                ("127.0.0.1", 2121), timeout=0.2
            ):
                print("FTP server is listening on 127.0.0.1:2121")
                return p
        except OSError:
            time.sleep(0.1)

    print("\nServer is still running but port 2121 is not accepting connections.")
    print("PID:", p.pid)

    # Read available output without blocking.
    import select
    ready, _, _ = select.select([p.stdout], [], [], 0)
    if ready:
        print("Server output:", p.stdout.readline().rstrip())

    p.terminate()
    try:
        p.wait(timeout=2)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()

    raise RuntimeError("FTP server did not listen on port 2121")

def login(user='admin'):
    f = ftplib.FTP(); f.connect('127.0.0.1',2121,timeout=5); f.login(user,'x'); return f

def attempt(label, fn):
    try:
        r = fn(); return f'{label}: OK {r!r}'
    except ftplib.all_errors as e:
        return f'{label}: DENIED {str(e)[:40]}'

def run(binary, follow, user='admin', root_suffix=''):
    setup(follow, root_suffix)
    p = start(binary)
    out = []
    try:
        f = login(user)
        def retr(path):
            b = io.BytesIO(); f.retrbinary('RETR '+path, b.write); return b.getvalue()
        def lst(c):
            r=[]; f.retrlines(c, r.append); return r
        out.append(attempt('CWD link', lambda: f.cwd('link')))
        f.cwd('/')
        out.append(attempt('RETR link/secret.txt', lambda: retr('link/secret.txt')))
        out.append(attempt('RETR real/sub/nested/secret.txt', lambda: retr('real/sub/nested/secret.txt')))
        out.append(attempt('RETR flink (final comp)', lambda: retr('flink')))
        out.append(attempt('LIST link', lambda: lst('LIST link')))
        out.append(attempt('STOR link/w.txt', lambda: f.storbinary('STOR link/w.txt', io.BytesIO(b'x'))))
        out.append(attempt('MKD link/newdir', lambda: f.mkd('link/newdir')))
        out.append(attempt('SIZE link/secret.txt', lambda: f.size('link/secret.txt')))
        out.append(attempt('DELE link/secret.txt', lambda: f.delete('link/secret.txt')))
        out.append(attempt('RETR link/../hello.txt (lexical ..)', lambda: retr('link/../hello.txt')))
        # regression: normal operation
        out.append(attempt('RETR hello.txt', lambda: retr('hello.txt')))
        out.append(attempt('RETR real/sub/deep.txt', lambda: retr('real/sub/deep.txt')))
        out.append(attempt('CWD real/sub', lambda: f.cwd('/real/sub')))
        f.cwd('/')
        out.append(attempt('STOR new.txt', lambda: f.storbinary('STOR new.txt', io.BytesIO(b'n'))))
        out.append(attempt('MKD newdir', lambda: f.mkd('newdir')))
        out.append(attempt('STOR newdir/x.txt', lambda: f.storbinary('STOR newdir/x.txt', io.BytesIO(b'n'))))
        out.append(attempt('RNFR/RNTO new.txt', lambda: f.rename('new.txt','new2.txt')))
        out.append(attempt('DELE new2.txt', lambda: f.delete('new2.txt')))
        out.append(attempt('LIST /', lambda: len(lst('LIST'))))
        out.append(attempt('MLSD link', lambda: lst('MLSD link')))
        out.append(attempt('MLSD real', lambda: len(lst('MLSD real'))))
        out.append(attempt('CWD inlink (in-root link)', lambda: f.cwd('inlink')))
        f.quit()
    finally:
        p.terminate(); p.wait()
    leaked = os.path.exists(BASE+'/outside/w.txt') or os.path.exists(BASE+'/outside/newdir')
    out.append(f'files created outside root: {leaked}; secret still present: {os.path.exists(BASE+"/outside/secret.txt")}')
    return out

if __name__=='__main__':
    binary, follow = sys.argv[1], sys.argv[2]
    user = sys.argv[3] if len(sys.argv)>3 else 'admin'
    suf = sys.argv[4] if len(sys.argv)>4 else ''
    print('\n'.join(run(binary, follow, user, suf)))
