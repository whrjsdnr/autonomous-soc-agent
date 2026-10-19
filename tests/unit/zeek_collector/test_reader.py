import pytest
from tests.zeek_collector_support import row

from soc_agent.security_ai.collectors.reader import LogReader


def test_partial_append_atomic_cursor_and_recovery(tmp_path):
    p = tmp_path / "conn.log"
    line = row()
    p.write_bytes(line[:20])
    reader = LogReader(p)
    assert reader.read() == ([], None)
    with pytest.raises(ValueError, match="PARTIAL_RECORD"):
        reader.finish()
    with p.open("ab") as f:
        f.write(line[20:])
    lines, cursor = reader.read()
    assert lines == [line] and cursor["offset"] == len(line)
    reader.close()
    resumed = LogReader(p, cursor)
    assert resumed.read() == ([], None)
    resumed.finish()
    resumed.close()


def test_rotation_drains_old_inode_and_new_file(tmp_path):
    p = tmp_path / "conn.log"
    first = row()
    second = row(uid="Cnext")
    p.write_bytes(first + second)
    reader = LogReader(p)
    assert reader.read(1)[0] == [first]
    p.rename(tmp_path / "conn.1.log")
    p.write_bytes(row(uid="Cnew"))
    assert reader.read(1)[0] == [second]
    assert reader.read(1)[0] == [row(uid="Cnew")]
    assert reader.rotations == 1
    reader.close()


@pytest.mark.parametrize("fault", ["truncate", "prefix", "recover_inode", "bound", "symlink"])
def test_fail_closed_log_integrity(tmp_path, fault):
    p = tmp_path / "conn.log"
    p.write_bytes(row())
    r = LogReader(p)
    _, cursor = r.read()
    try:
        if fault == "truncate":
            p.write_bytes(b"")
            r.read()
        elif fault == "prefix":
            p.write_bytes(row(uid="Dfixture"))
            r.read()
        elif fault == "recover_inode":
            r.close()
            p.rename(tmp_path / "old")
            p.write_bytes(row())
            LogReader(p, cursor).read()
        elif fault == "bound":
            r.read(257)
        else:
            r.close()
            p.rename(tmp_path / "old")
            p.symlink_to(tmp_path / "old")
            LogReader(p).read()
    except (ValueError, OSError):
        pass
    else:
        pytest.fail("Invalid log accepted")
    finally:
        r.close()
