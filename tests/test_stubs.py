from truthgate import stubs as STUBS


def kinds(source, *, filename="module.py"):
    return [(finding.qualified_name, finding.kind) for finding in STUBS.find_stubs(source, filename=filename)]


def test_detects_hollow_function_bodies():
    source = '''
def with_pass():
    pass

async def with_ellipsis():
    """Not implemented yet."""
    ...

def with_raise():
    raise NotImplementedError("later")

def bare_return():
    return

def explicit_none():
    return None
'''
    assert kinds(source) == [
        ("with_pass", "pass"),
        ("with_ellipsis", "ellipsis"),
        ("with_raise", "not_implemented"),
        ("bare_return", "return_none"),
        ("explicit_none", "return_none"),
    ]


def test_literal_return_requires_adjacent_placeholder_comment():
    source = '''
def real_constant():
    return 42

def inline_placeholder():
    return "temporary"  # TODO: replace with real result

def preceding_placeholder():
    # FIXME implement lookup
    return []

def separated_comment():
    # TODO eventually calculate this

    return False
'''
    assert kinds(source) == [
        ("inline_placeholder", "placeholder_return"),
        ("preceding_placeholder", "placeholder_return"),
    ]


def test_only_hollow_whole_implementations_are_reported():
    source = '''
class Container:
    pass

def real_branch(flag):
    if flag:
        pass
    return 1

def catches_expected_error():
    try:
        return work()
    except LookupError:
        raise NotImplementedError
'''
    assert kinds(source) == []


def test_excludes_abstract_overload_protocol_and_allow_annotations():
    source = '''
from abc import abstractmethod
from typing import overload, Protocol

class Service:
    @abstractmethod
    def abstract(self):
        pass

    @typing.overload
    def overloaded(self, value: int): ...

class Reader(Protocol):
    def read(self) -> bytes: ...

def explicitly_allowed():
    pass  # truthgate: allow
'''
    assert kinds(source) == []


def test_reports_nested_names_and_ignores_stub_files():
    source = '''
class Worker:
    def execute(self):
        def inner():
            pass
        return inner
'''
    assert kinds(source) == [("Worker.execute.inner", "pass")]
    assert kinds("def declared(): ...\n", filename="api.pyi") == []


def test_invalid_source_fails_open():
    assert STUBS.find_stubs("def broken(:\n", filename="broken.py") == ()
