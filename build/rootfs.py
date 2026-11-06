"""Assemble a shell-free runtime from the architecture's signed Debian packages."""
import os
import pwd
import re
import shutil
import subprocess
import sys
import sysconfig
import zipfile
from pathlib import Path

ROOT = Path("/rootfs")
ARCH_LIB = Path("/usr/lib") / sysconfig.get_config_var("MULTIARCH")
STDLIB = Path(sysconfig.get_path("stdlib"))
APP = Path("/opt/sipdock")
copied = {}


def copy(source):
    source = Path(source)
    target = ROOT / source.relative_to("/")
    if target.exists():
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    original = source.resolve()
    if original in copied:
        os.link(copied[original], target)
    else:
        shutil.copy2(source, target)
        copied[original] = target


def executable(source):
    copy(source)
    listing = subprocess.check_output(["ldd", str(source)], text=True)
    if "not found" in listing:
        raise RuntimeError(f"unresolved library for {source}: {listing}")
    for path in re.findall(r"(?:=>\s+|^\s*)(/\S+)\s+\(", listing, re.MULTILINE):
        copy(path)


for name in ("kamailio", "iptables-restore", "ip6tables-restore", "python3"):
    path = Path(shutil.which(name))
    executable(path.resolve())
    target = ROOT / path.relative_to("/")
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(path.resolve())

for module in re.findall(r'^loadmodule "(\w+\.so)"', (APP / "kamailio.cfg").read_text(), re.MULTILINE):
    executable(ARCH_LIB / "kamailio/modules" / module)
for module in ("xt_standard", "xt_tcp", "xt_udp", "xt_conntrack", "ip6t_hl", "ip6t_icmp6"):
    executable(ARCH_LIB / "xtables" / f"lib{module}.so")

# Keep Python source compressed in its native stdlib zip path. Preserve mail,
# DNS, TLS, codecs and the full YAML parser. Native extensions load from disk.
stdlib_zip = ROOT / f"usr/lib/python{sys.version_info.major}{sys.version_info.minor}.zip"
omit = {"test", "tests", "tkinter", "idlelib", "turtledemo", "ensurepip", "lib2to3",
        "pydoc_data", "venv", "dist-packages", "site-packages", "__pycache__",
        "asyncio", "multiprocessing", "unittest", "xmlrpc", "wsgiref", "_pyrepl"}
with zipfile.ZipFile(stdlib_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for path in sorted(STDLIB.rglob("*.py")):
        relative = path.relative_to(STDLIB)
        if not omit.intersection(relative.parts):
            archive.write(path, str(relative))
    for path in sorted(Path("/usr/lib/python3/dist-packages/yaml").glob("*.py")):
        archive.write(path, "yaml/" + path.name)

# Other compiled extensions are supplied by CPython itself on some architectures.
native = {"_bisect", "_blake2", "_bz2", "_datetime", "_hashlib", "_heapq", "_json", "_lzma",
          "_md5", "_opcode", "_posixsubprocess", "_queue", "_random", "_sha1", "_sha2",
          "_sha3", "_socket", "_sqlite3", "_ssl", "_struct", "_uuid", "array", "binascii",
          "fcntl", "math", "select", "unicodedata", "zlib"}
for path in (STDLIB / "lib-dynload").glob("*.so"):
    if path.name.partition(".")[0] in native:
        executable(path)

for path in ("/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/openssl.cnf",
             "/etc/nsswitch.conf", "/etc/services", "/etc/protocols",
             "/usr/share/kamailio/db_sqlite/standard-create.sql",
             "/usr/share/kamailio/db_sqlite/uac-create.sql"):
    copy(path)
for path in APP.iterdir():
    copy(path)

# Retain the notices of shipped packages, including Python and the zipped YAML
# sources. Debian's merged /usr may record a library under either path.
shipped = set(copied) | {Path(sysconfig.__file__), Path("/usr/lib/python3/dist-packages/yaml/__init__.py")}
for listing in Path("/var/lib/dpkg/info").glob("*.list"):
    files = listing.read_text().splitlines()
    if any(Path(name) in shipped or Path("/usr" + name) in shipped for name in files):
        package = listing.stem.split(":")[0]
        notice = Path("/usr/share/doc") / package / "copyright"
        if notice.is_file():
            copy(notice)
for path in Path("/usr/share/common-licenses").iterdir():
    copy(path)

account = pwd.getpwnam("kamailio")
for name in ("passwd", "group"):
    lines = Path("/etc", name).read_text().splitlines()
    (ROOT / "etc" / name).write_text("".join(line + "\n" for line in lines if line.split(":")[0] in {"root", "kamailio"}))
for dirname in ("run/sipdock", "var/run/kamailio"):
    run = ROOT / dirname
    run.mkdir(parents=True, mode=0o700)
    os.chown(run, account.pw_uid, account.pw_gid)
(ROOT / "tmp").mkdir()
(ROOT / "tmp").chmod(0o1777)
